#!/usr/bin/env python3
"""Classify speeches into substantive / explanation_of_vote / procedural.

Adds a ``speech_type`` column to the ``speeches`` table and populates it
using three rules applied in priority order (later rules override earlier):

1. **substantive** — the default; set for every speech that doesn't match
   a higher-priority rule.

2. **explanation_of_vote** — speech inside an agenda item that contains at
   least one *recorded* vote, whose ``position_in_item`` is *after* that of
   any recorded vote in the same item.  These are the post-vote statements
   where delegates explain their position — the most policy-relevant content
   around a vote.

3. **procedural** — speech by a presiding officer: speaker whose name starts
   with ``The `` (e.g. *The President*, *The Secretary-General*, *The
   Chairman*) or whose ``role`` is one of the recognised titular roles.
   Procedural speeches take priority over explanation_of_vote: if the
   President speaks after a vote to announce results, that is procedural, not
   an explanation of vote.

The script is safe to re-run: it always recomputes all three labels from
scratch in a single transaction.  Use ``--dry-run`` to preview counts.

Usage
-----
    python scripts/tag_speech_types.py
    python scripts/tag_speech_types.py --db postgresql://...
    python scripts/tag_speech_types.py --dry-run
    python scripts/tag_speech_types.py --body GA
    python scripts/tag_speech_types.py --body SC
    python scripts/tag_speech_types.py --verbose
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

# Names of presiding officers — stored verbatim in speakers.name
# These are matched case-insensitively with a LIKE 'The %' prefix check.
_TITULAR_ROLES = frozenset(
    {
        "president",
        "secretary-general",
        "chairman",
        "chairwoman",
        "chairperson",
        "deputy secretary-general",
        "acting president",
        "director-general",
    }
)


# ---------------------------------------------------------------------------
# Schema migration
# ---------------------------------------------------------------------------


def _ensure_column(session: Session) -> None:
    """Add speech_type column to speeches if not already present."""
    # PostgreSQL
    if session.get_bind().dialect.name == "postgresql":
        session.execute(
            text(
                "ALTER TABLE speeches "
                "ADD COLUMN IF NOT EXISTS speech_type VARCHAR(30)"
            )
        )
        session.commit()
    else:
        # SQLite: check manually
        cols = {
            row[1]
            for row in session.execute(text("PRAGMA table_info(speeches)")).fetchall()
        }
        if "speech_type" not in cols:
            session.execute(
                text("ALTER TABLE speeches ADD COLUMN speech_type VARCHAR(30)")
            )
            session.commit()


# ---------------------------------------------------------------------------
# Tagging passes
# ---------------------------------------------------------------------------


def tag_speeches(
    session: Session,
    body: str | None = None,
    dry_run: bool = False,
) -> dict[str, int]:
    """Run all three tagging passes and return {label: count} from final DB state."""
    params: dict[str, object] = {}
    body_doc_filter = ""
    if body:
        params["body"] = body.upper()
        body_doc_filter = (
            " AND document_id IN (SELECT id FROM documents WHERE body = :body)"
        )

    roles_in = ", ".join(f"'{r}'" for r in sorted(_TITULAR_ROLES))

    # Portable correlated-subquery WHERE clause for EOV speeches.
    # Works in both SQLite and PostgreSQL.
    eov_where = (
        "item_id IS NOT NULL"
        " AND item_id IN ("
        "   SELECT item_id FROM votes"
        "   WHERE vote_type = 'recorded' AND item_id IS NOT NULL"
        " )"
        " AND position_in_item > ("
        "   SELECT MIN(v.position_in_item) FROM votes v"
        "   WHERE v.vote_type = 'recorded' AND v.item_id = speeches.item_id"
        " )"
    )

    # WHERE clause for procedural speeches (speaker is a presiding officer).
    proc_where = (
        "speaker_id IN ("
        "  SELECT id FROM speakers"
        f"  WHERE LOWER(name) LIKE 'the %' OR LOWER(role) IN ({roles_in})"
        ")"
    )

    if dry_run:
        n_total = (
            session.execute(
                text(f"SELECT COUNT(*) FROM speeches WHERE 1=1{body_doc_filter}"),
                params,
            ).scalar()
            or 0
        )
        n_eov = (
            session.execute(
                text(
                    f"SELECT COUNT(*) FROM speeches WHERE {eov_where}{body_doc_filter}"
                ),
                params,
            ).scalar()
            or 0
        )
        n_proc = (
            session.execute(
                text(
                    f"SELECT COUNT(*) FROM speeches WHERE {proc_where}{body_doc_filter}"
                ),
                params,
            ).scalar()
            or 0
        )
        return {
            "substantive": n_total - n_eov - n_proc,
            "explanation_of_vote": n_eov,
            "procedural": n_proc,
        }

    # Pass 1: default all to substantive
    session.execute(
        text(
            f"UPDATE speeches SET speech_type = 'substantive' WHERE 1=1{body_doc_filter}"
        ),
        params,
    )

    # Pass 2: post-vote speeches → explanation_of_vote
    session.execute(
        text(
            f"UPDATE speeches SET speech_type = 'explanation_of_vote'"
            f" WHERE {eov_where}{body_doc_filter}"
        ),
        params,
    )

    # Pass 3: presiding officers → procedural (overrides EOV)
    session.execute(
        text(
            f"UPDATE speeches SET speech_type = 'procedural'"
            f" WHERE {proc_where}{body_doc_filter}"
        ),
        params,
    )

    session.commit()

    # Report final distribution from DB
    count_sql = (
        f"SELECT speech_type, COUNT(*) FROM speeches"
        f" WHERE 1=1{body_doc_filter}"
        f" GROUP BY speech_type"
    )
    rows = session.execute(text(count_sql), params).fetchall()
    return {(r[0] or "null"): r[1] for r in rows}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Classify speeches as substantive / explanation_of_vote / procedural.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument("--body", default=None, choices=["GA", "SC"])
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
        _ensure_column(session)
        counts = tag_speeches(session, body=args.body, dry_run=args.dry_run)

    action = "Would tag" if args.dry_run else "Tagged"
    log.info(
        "%s %d substantive, %d explanation_of_vote, %d procedural",
        action,
        counts["substantive"],
        counts["explanation_of_vote"],
        counts["procedural"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
