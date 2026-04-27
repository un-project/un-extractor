#!/usr/bin/env python3
"""Compute per-year country co-sponsorship network centrality scores.

For each year, builds a weighted co-sponsorship graph from resolution_sponsors:
  - Nodes  : countries with at least one co-sponsorship that year
  - Edges  : pairs of countries that co-sponsored the same resolution
  - Weight : number of resolutions co-sponsored together

Metrics computed
----------------
  PageRank          — weighted PageRank (damping 0.85, power iteration).
                      Captures overall influence in the network.
  Betweenness       — normalised betweenness centrality (unweighted BFS,
                      Brandes 2001).  Captures bridging / brokerage roles.

Both algorithms are implemented in pure Python; the graph is small (≤ 193
nodes) so no external graph library is required.

Results are written to ``country_network_stats``:
    (country_id, year, pagerank, betweenness)

Re-running is safe: rows for the target year(s) are deleted before insert.

Usage
-----
    python scripts/compute_country_network.py --db postgresql://...
    python scripts/compute_country_network.py --year 2022 --db ...
    python scripts/compute_country_network.py --year-from 2000 --year-to 2024
    python scripts/compute_country_network.py --min-cosponsors 2 --dry-run
    python scripts/compute_country_network.py --verbose --db ...
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections import defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402

log = logging.getLogger(__name__)

_DEFAULT_DAMPING = 0.85
_DEFAULT_MAX_ITER = 200
_DEFAULT_TOL = 1e-7
_DEFAULT_MIN_COSPONSORS = 1   # minimum shared resolutions to form an edge


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def _ensure_schema(session: Session) -> None:
    session.execute(text("""
        CREATE TABLE IF NOT EXISTS country_network_stats (
            id           SERIAL  PRIMARY KEY,
            country_id   INTEGER NOT NULL REFERENCES countries(id) ON DELETE CASCADE,
            year         INTEGER NOT NULL,
            pagerank     DOUBLE PRECISION NOT NULL,
            betweenness  DOUBLE PRECISION NOT NULL,
            n_edges      INTEGER NOT NULL,
            UNIQUE (country_id, year)
        )
    """))
    session.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_cns_country "
        "ON country_network_stats (country_id)"
    ))
    session.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_cns_year "
        "ON country_network_stats (year)"
    ))
    session.commit()
    log.info("country_network_stats schema ready.")


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


_YEAR_SQL = """
    -- Resolve the year for each (country, resolution) co-sponsorship row.
    --
    -- Priority:
    --   1. Earliest date of any vote document for this resolution (most accurate).
    --   2. GA session number: session + 1945  (e.g. session 75 → 2020).
    --   3. Year embedded in SC draft symbol:  S/YYYY/N  (e.g. S/2020/891 → 2020).
    --
    -- Resolutions that cannot be dated by any method are excluded.
    SELECT country_id, resolution_id, year
    FROM (
        SELECT rs.country_id,
               rs.resolution_id,
               COALESCE(
                   MIN(EXTRACT(YEAR FROM d.date)::int),
                   CASE
                       WHEN r.body = 'GA' AND r.session IS NOT NULL
                       THEN r.session + 1945
                       WHEN r.body = 'SC'
                       THEN (regexp_match(r.draft_symbol, '^S/([12][0-9]{3})/'))[ 1]::int
                   END
               ) AS year
        FROM   resolution_sponsors rs
        JOIN   resolutions r  ON r.id  = rs.resolution_id
        LEFT JOIN votes v     ON v.resolution_id = rs.resolution_id
        LEFT JOIN documents d ON d.id = v.document_id AND d.date IS NOT NULL
        WHERE  rs.country_id IS NOT NULL
        GROUP  BY rs.country_id, rs.resolution_id, r.body, r.session, r.draft_symbol
    ) sub
    WHERE year BETWEEN 1946 AND 2100
    ORDER BY year
"""


def _get_years(
    session: Session,
    year: int | None,
    year_from: int | None,
    year_to: int | None,
) -> list[int]:
    if year is not None:
        return [year]
    rows = session.execute(text(f"""
        SELECT DISTINCT year FROM ({_YEAR_SQL}) all_rows ORDER BY year
    """)).fetchall()
    years = [r[0] for r in rows if r[0] is not None]
    if year_from is not None:
        years = [y for y in years if y >= year_from]
    if year_to is not None:
        years = [y for y in years if y <= year_to]
    return years


def _load_cosponsors(session: Session) -> dict[int, dict[int, set[int]]]:
    """Return {year: {resolution_id: {country_id, ...}}}.

    Year is resolved in priority order: vote-document date → GA session →
    SC draft-symbol year.  Resolutions without any of these are excluded.
    """
    rows = session.execute(text(_YEAR_SQL)).fetchall()

    result: dict[int, dict[int, set[int]]] = defaultdict(lambda: defaultdict(set))
    for country_id, res_id, year in rows:
        result[year][res_id].add(int(country_id))
    log.info(
        "Loaded co-sponsorship data: %d years, %d (country, resolution) pairs.",
        len(result),
        len(rows),
    )
    return result


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

# Adjacency: adj[u][v] = edge weight (number of co-sponsored resolutions)
Adj = dict[int, dict[int, float]]


def _build_graph(
    res_dict: dict[int, set[int]],
    min_cosponsors: int,
) -> Adj:
    """Build weighted undirected adjacency from {resolution_id: {country_ids}}."""
    raw: dict[tuple[int, int], int] = defaultdict(int)
    for countries in res_dict.values():
        lst = sorted(countries)
        for i, a in enumerate(lst):
            for b in lst[i + 1:]:
                raw[(a, b)] += 1

    adj: Adj = defaultdict(dict)
    for (a, b), w in raw.items():
        if w >= min_cosponsors:
            adj[a][b] = float(w)
            adj[b][a] = float(w)

    # Ensure isolated nodes (co-sponsors of only one resolution) are present
    for countries in res_dict.values():
        for c in countries:
            if c not in adj:
                adj[c] = {}

    return dict(adj)


# ---------------------------------------------------------------------------
# PageRank (weighted power iteration)
# ---------------------------------------------------------------------------


def _pagerank(
    adj: Adj,
    damping: float = _DEFAULT_DAMPING,
    max_iter: int = _DEFAULT_MAX_ITER,
    tol: float = _DEFAULT_TOL,
) -> dict[int, float]:
    nodes = list(adj)
    n = len(nodes)
    if n == 0:
        return {}

    out_strength = {u: sum(adj[u].values()) for u in nodes}
    dangling_nodes = [u for u in nodes if out_strength[u] == 0.0]

    pr = {u: 1.0 / n for u in nodes}
    for _ in range(max_iter):
        # Dangling mass is redistributed uniformly
        dangling_sum = sum(pr[u] for u in dangling_nodes)
        new_pr = {u: (1 - damping) / n + damping * dangling_sum / n for u in nodes}
        for u in nodes:
            s = out_strength[u]
            if s == 0.0:
                continue
            share = damping * pr[u] / s
            for v, w in adj[u].items():
                new_pr[v] += share * w

        err = sum(abs(new_pr[u] - pr[u]) for u in nodes)
        pr = new_pr
        if err < tol:
            break

    return pr


# ---------------------------------------------------------------------------
# Betweenness centrality (Brandes 2001, unweighted BFS)
# ---------------------------------------------------------------------------


def _betweenness(adj: Adj) -> dict[int, float]:
    nodes = list(adj)
    n = len(nodes)
    bc: dict[int, float] = {u: 0.0 for u in nodes}

    for s in nodes:
        stack: list[int] = []
        pred: dict[int, list[int]] = {w: [] for w in nodes}
        sigma: dict[int, float] = {w: 0.0 for w in nodes}
        sigma[s] = 1.0
        dist: dict[int, int] = {w: -1 for w in nodes}
        dist[s] = 0
        q: deque[int] = deque([s])

        while q:
            v = q.popleft()
            stack.append(v)
            for w in adj.get(v, {}):
                if dist[w] < 0:
                    q.append(w)
                    dist[w] = dist[v] + 1
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)

        delta: dict[int, float] = {w: 0.0 for w in nodes}
        while stack:
            w = stack.pop()
            for v in pred[w]:
                if sigma[w] > 0.0:
                    delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
            if w != s:
                bc[w] += delta[w]

    # Normalise for undirected graph: divide by (n-1)(n-2)
    if n > 2:
        scale = 1.0 / ((n - 1) * (n - 2))
        bc = {u: bc[u] * scale for u in nodes}

    return bc


# ---------------------------------------------------------------------------
# Per-year processing
# ---------------------------------------------------------------------------


def _process_year(
    session: Session,
    year: int,
    res_dict: dict[int, set[int]],
    min_cosponsors: int,
    dry_run: bool,
) -> int:
    """Compute and upsert centrality scores for one year. Returns node count."""
    adj = _build_graph(res_dict, min_cosponsors)
    n_nodes = len(adj)
    if n_nodes < 2:
        log.debug("  %d: fewer than 2 nodes — skipping.", year)
        return 0

    n_edges = sum(len(v) for v in adj.values()) // 2
    if n_edges == 0:
        # All nodes are isolated: PageRank degenerates to 1/n and betweenness
        # to 0 for every country — not meaningful. Skip rather than write noise.
        log.warning(
            "  %d: %d countries but 0 edges — co-sponsorship data too sparse, skipping.",
            year, n_nodes,
        )
        return 0

    pr = _pagerank(adj)
    bc = _betweenness(adj)

    if not dry_run:
        session.execute(
            text("DELETE FROM country_network_stats WHERE year = :y"),
            {"y": year},
        )
        for country_id in adj:
            n_edges = len(adj[country_id])
            session.execute(
                text("""
                    INSERT INTO country_network_stats
                        (country_id, year, pagerank, betweenness, n_edges)
                    VALUES (:cid, :y, :pr, :bc, :ne)
                    ON CONFLICT (country_id, year)
                    DO UPDATE SET pagerank    = EXCLUDED.pagerank,
                                  betweenness = EXCLUDED.betweenness,
                                  n_edges     = EXCLUDED.n_edges
                """),
                {
                    "cid": country_id,
                    "y": year,
                    "pr": pr[country_id],
                    "bc": bc[country_id],
                    "ne": n_edges,
                },
            )
        session.commit()

    return n_nodes


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run(
    session: Session,
    year: int | None = None,
    year_from: int | None = None,
    year_to: int | None = None,
    min_cosponsors: int = _DEFAULT_MIN_COSPONSORS,
    dry_run: bool = False,
) -> None:
    _ensure_schema(session)
    years = _get_years(session, year, year_from, year_to)
    log.info(
        "Computing network centrality for %d year(s) (min_cosponsors=%d)%s.",
        len(years),
        min_cosponsors,
        " [dry-run]" if dry_run else "",
    )

    all_data = _load_cosponsors(session)

    for y in years:
        res_dict = all_data.get(y, {})
        if not res_dict:
            log.debug("  %d: no co-sponsorship data — skipping.", y)
            continue
        n = _process_year(session, y, res_dict, min_cosponsors, dry_run)
        if n:
            log.info("  %d: %d countries, %d resolutions.", y, n, len(res_dict))

    log.info("Done.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Compute per-year co-sponsorship network centrality (PageRank + betweenness).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument("--year", type=int, default=None, help="Process a single year")
    p.add_argument("--year-from", type=int, default=None, dest="year_from")
    p.add_argument("--year-to", type=int, default=None, dest="year_to")
    p.add_argument(
        "--min-cosponsors",
        type=int,
        default=_DEFAULT_MIN_COSPONSORS,
        dest="min_cosponsors",
        help="Minimum co-sponsored resolutions to form a graph edge",
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

    import os
    db_url = args.db or os.environ.get("DATABASE_URL")
    if not db_url:
        parser.error("--db or $DATABASE_URL is required")

    engine = get_engine(db_url)
    create_schema(engine)

    with get_session(engine) as session:
        run(
            session,
            year=args.year,
            year_from=args.year_from,
            year_to=args.year_to,
            min_cosponsors=args.min_cosponsors,
            dry_run=args.dry_run,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
