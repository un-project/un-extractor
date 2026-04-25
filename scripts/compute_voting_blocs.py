#!/usr/bin/env python3
"""Compute data-driven voting blocs via connected-component clustering.

For each calendar year, builds a 5-year rolling window of country_votes,
computes pairwise agreement rates, and groups countries whose agreement
exceeds a threshold into blocs.  Results are written to the ``voting_blocs``
table.

Algorithm
---------
1. For the window [year-2, year+2], compute for every pair of countries the
   fraction of resolutions on which they cast the same vote (yes/no/abstain).
   Non-voting / absent ballots are excluded from both numerator and denominator.
   Only *recorded* GA votes are used; SC has far fewer votes and skews results.
2. Build an adjacency graph: an edge exists between two countries if their
   agreement rate meets ``--threshold`` AND they share at least ``--min-shared``
   votes.
3. Find connected components via union-find; assign each component a
   ``bloc_index`` (0 = largest bloc).
4. DELETE existing rows for the year and INSERT the new assignment.

The script is safe to re-run: each year is processed atomically (DELETE +
INSERT inside a single transaction per year).

Ported from
-----------
  ~/Code/un-project.org/votes/management/commands/compute_voting_blocs.py
  (Django management command; logic is identical, Django dependency removed)

Usage
-----
    python scripts/compute_voting_blocs.py
    python scripts/compute_voting_blocs.py --db postgresql://...
    python scripts/compute_voting_blocs.py --year 2022
    python scripts/compute_voting_blocs.py --year-from 2010 --year-to 2023
    python scripts/compute_voting_blocs.py --threshold 0.80 --min-shared 25
    python scripts/compute_voting_blocs.py --dry-run
    python scripts/compute_voting_blocs.py --verbose
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402

log = logging.getLogger(__name__)

_WINDOW_HALF = 2  # window = [year - 2, year + 2]
_DEFAULT_THRESHOLD = 0.75
_DEFAULT_MIN_SHARED = 30


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def _ensure_schema(session: Session) -> None:
    session.execute(text("""
            CREATE TABLE IF NOT EXISTS voting_blocs (
                id           SERIAL  PRIMARY KEY,
                country_id   INTEGER NOT NULL,
                year         INTEGER NOT NULL,
                bloc_index   INTEGER NOT NULL,
                window_start INTEGER NOT NULL,
                window_end   INTEGER NOT NULL
            )
            """))
    session.execute(
        text(
            "CREATE UNIQUE INDEX IF NOT EXISTS voting_blocs_country_year "
            "ON voting_blocs (country_id, year)"
        )
    )
    session.execute(
        text("CREATE INDEX IF NOT EXISTS voting_blocs_year " "ON voting_blocs (year)")
    )
    session.commit()


# ---------------------------------------------------------------------------
# Year discovery
# ---------------------------------------------------------------------------


def _get_years(
    session: Session,
    year: int | None,
    year_from: int | None,
    year_to: int | None,
) -> list[int]:
    if year is not None:
        return [year]
    rows = session.execute(text("""
            SELECT DISTINCT EXTRACT(YEAR FROM d.date)::int
            FROM   country_votes cv
            JOIN   votes v  ON v.id  = cv.vote_id
            JOIN   documents d ON d.id = v.document_id
            WHERE  d.date IS NOT NULL
              AND  EXTRACT(YEAR FROM d.date) > 1900
            ORDER  BY 1
            """)).fetchall()
    years = [r[0] for r in rows]
    if year_from is not None:
        years = [y for y in years if y >= year_from]
    if year_to is not None:
        years = [y for y in years if y <= year_to]
    return years


# ---------------------------------------------------------------------------
# Union-find
# ---------------------------------------------------------------------------


def _make_uf(nodes: set[int]) -> dict[int, int]:
    return {n: n for n in nodes}


def _find(parent: dict[int, int], x: int) -> int:
    while parent[x] != x:
        parent[x] = parent[parent[x]]  # path compression
        x = parent[x]
    return x


def _union(parent: dict[int, int], x: int, y: int) -> None:
    rx, ry = _find(parent, x), _find(parent, y)
    if rx != ry:
        parent[rx] = ry


# ---------------------------------------------------------------------------
# Per-year processing
# ---------------------------------------------------------------------------


def _process_year(
    session: Session,
    year: int,
    threshold: float,
    min_shared: int,
    dry_run: bool,
) -> tuple[int, int]:
    """Compute blocs for one year.  Returns (n_countries, n_blocs)."""
    win_start = year - _WINDOW_HALF
    win_end = year + _WINDOW_HALF

    rows = session.execute(
        text("""
            SELECT cv1.country_id,
                   cv2.country_id,
                   SUM(CASE WHEN cv1.vote_position = cv2.vote_position
                            THEN 1 ELSE 0 END)::float / COUNT(*) AS agree,
                   COUNT(*) AS shared
            FROM   country_votes cv1
            JOIN   country_votes cv2
                ON cv1.vote_id = cv2.vote_id
               AND cv1.country_id < cv2.country_id
            JOIN   votes v  ON v.id  = cv1.vote_id
            JOIN   documents d ON d.id = v.document_id
            WHERE  EXTRACT(YEAR FROM d.date) BETWEEN :win_start AND :win_end
              AND  d.date IS NOT NULL
              AND  EXTRACT(YEAR FROM d.date) > 1900
              AND  d.body = 'GA'
              AND  v.vote_type = 'recorded'
              AND  cv1.vote_position IN ('yes', 'no', 'abstain')
              AND  cv2.vote_position IN ('yes', 'no', 'abstain')
            GROUP  BY cv1.country_id, cv2.country_id
            HAVING COUNT(*) >= :min_shared
            """),
        {"win_start": win_start, "win_end": win_end, "min_shared": min_shared},
    ).fetchall()

    if not rows:
        log.debug("  %d: no pairs found — skipping", year)
        return 0, 0

    # Build adjacency from pairs above threshold
    all_countries: set[int] = set()
    adj: dict[int, set[int]] = {}
    for a, b, agree, _shared in rows:
        all_countries.add(a)
        all_countries.add(b)
        if agree >= threshold:
            adj.setdefault(a, set()).add(b)
            adj.setdefault(b, set()).add(a)

    # Connected components via union-find
    parent = _make_uf(all_countries)
    for node, neighbours in adj.items():
        for nb in neighbours:
            _union(parent, node, nb)

    # Group by root, sort by descending size, assign bloc_index
    groups: dict[int, list[int]] = {}
    for c in all_countries:
        groups.setdefault(_find(parent, c), []).append(c)
    blocs = sorted(groups.values(), key=len, reverse=True)

    n_countries = len(all_countries)
    n_blocs = len(blocs)

    if not dry_run:
        session.execute(
            text("DELETE FROM voting_blocs WHERE year = :year"), {"year": year}
        )
        for idx, members in enumerate(blocs):
            for country_id in members:
                session.execute(
                    text(
                        "INSERT INTO voting_blocs "
                        "(country_id, year, bloc_index, window_start, window_end) "
                        "VALUES (:cid, :year, :idx, :ws, :we)"
                    ),
                    {
                        "cid": country_id,
                        "year": year,
                        "idx": idx,
                        "ws": win_start,
                        "we": win_end,
                    },
                )
        session.commit()

    return n_countries, n_blocs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run(
    session: Session,
    year: int | None = None,
    year_from: int | None = None,
    year_to: int | None = None,
    threshold: float = _DEFAULT_THRESHOLD,
    min_shared: int = _DEFAULT_MIN_SHARED,
    dry_run: bool = False,
) -> None:
    _ensure_schema(session)
    years = _get_years(session, year, year_from, year_to)
    log.info(
        "Computing blocs for %d year(s) (threshold=%.2f, min_shared=%d)%s",
        len(years),
        threshold,
        min_shared,
        " [dry-run]" if dry_run else "",
    )

    for y in years:
        n_countries, n_blocs = _process_year(session, y, threshold, min_shared, dry_run)
        if n_countries:
            log.info("  %d: %d countries → %d blocs", y, n_countries, n_blocs)

    log.info("Done.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Compute data-driven voting blocs via connected-component clustering.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument("--year", type=int, default=None, help="Process a single year")
    p.add_argument("--year-from", type=int, default=None, dest="year_from")
    p.add_argument("--year-to", type=int, default=None, dest="year_to")
    p.add_argument(
        "--threshold",
        type=float,
        default=_DEFAULT_THRESHOLD,
        help="Agreement fraction threshold",
    )
    p.add_argument(
        "--min-shared",
        type=int,
        default=_DEFAULT_MIN_SHARED,
        dest="min_shared",
        help="Minimum shared votes per country pair",
    )
    p.add_argument("--dry-run", action="store_true", default=False)
    p.add_argument("--verbose", action="store_true", default=False)
    return p


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    engine = get_engine(args.db)
    create_schema(engine)

    with get_session(engine) as session:
        run(
            session,
            year=args.year,
            year_from=args.year_from,
            year_to=args.year_to,
            threshold=args.threshold,
            min_shared=args.min_shared,
            dry_run=args.dry_run,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
