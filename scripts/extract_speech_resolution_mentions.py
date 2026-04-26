#!/usr/bin/env python3
"""Extract resolution symbol mentions from speech text.

Scans ``speeches.text`` for resolution symbol references and populates
``speech_resolution_mentions``:

    speech_id     INTEGER NOT NULL REFERENCES speeches(id) ON DELETE CASCADE
    cited_symbol  TEXT NOT NULL          -- normalized extracted symbol
    resolution_id INTEGER REFERENCES resolutions(id) ON DELETE SET NULL

This is the speech-side complement to ``resolution_citations`` (which records
resolution-to-resolution references in resolution text).  Together they
provide two perspectives on the citation graph:

  - ``resolution_citations``          — resolution cites resolution
  - ``speech_resolution_mentions``    — speech mentions resolution

The ``resolution_id`` FK is best-effort: populated when the cited symbol
matches a known ``draft_symbol`` or ``adopted_symbol`` in the DB.  A second
backfill pass fills in any NULL FKs for rows added before the corresponding
resolution was imported.

Patterns matched
----------------
1. **Explicit draft symbols** — ``A/64/L.72``, ``A/C.3/78/L.5/Rev.1``
2. **Explicit adopted symbols** — ``A/RES/64/299``, ``S/RES/1441``,
   ``S/RES/1441(2002)``
3. **Natural-language GA** — "resolution 64/299" (inferred ``A/RES/`` prefix)
4. **Natural-language SC** — "resolution 1441" or "resolution 1441 (2002)"
   (inferred ``S/RES/`` prefix)

Symbols are deduplicated per speech: ``UNIQUE (speech_id, cited_symbol)``.
The script is safe to re-run (``ON CONFLICT DO UPDATE``).

Usage
-----
    python scripts/extract_speech_resolution_mentions.py
    python scripts/extract_speech_resolution_mentions.py --db postgresql://...
    python scripts/extract_speech_resolution_mentions.py --dry-run
    python scripts/extract_speech_resolution_mentions.py --body GA
    python scripts/extract_speech_resolution_mentions.py --body SC
    python scripts/extract_speech_resolution_mentions.py --backfill-only
    python scripts/extract_speech_resolution_mentions.py --verbose
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402
from src.db.models import Resolution  # noqa: E402

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Explicit draft symbols: A/64/L.72, A/C.3/78/L.5/Rev.1, A/C.6/79/L.3
_DRAFT_SYMBOL_RE = re.compile(
    r"\b(A/(?:C\.\d+/\d+/|\d+/)L\.\d+(?:/Rev\.\d+)?)\b",
    re.IGNORECASE,
)

# Explicit adopted symbols with full prefix:
#   A/RES/64/299, S/RES/1441, S/RES/1441(2002)
_ADOPTED_FULL_RE = re.compile(
    r"\b((?:A/RES/\d{1,3}/\d{1,4}|S/RES/\d{3,4}(?:\(\d{4}\))?))\b",
    re.IGNORECASE,
)

# Natural-language GA: "resolution 64/299" (session/number, no prefix)
_GA_TEXT_RE = re.compile(
    r"\bresolution\s+(\d{1,3}/\d{1,4})\b",
    re.IGNORECASE,
)

# Natural-language SC: "resolution 1441" or "resolution 1441 (2002)"
# Only 3-4 digit numbers to avoid matching GA session/number patterns.
_SC_TEXT_RE = re.compile(
    r"\bresolution\s+(\d{3,4})(?:\s*\(\d{4}\))?\b",
    re.IGNORECASE,
)

# Suppress false positives for SC numbers that look like years or small counts
_MIN_SC_RES_NUM = 100  # SC resolutions only since 1946; res #1 is too short

# Sentences that mention the resolution of this very meeting (the one being
# voted on) are still useful to record — don't filter them out.


# ---------------------------------------------------------------------------
# Symbol extraction
# ---------------------------------------------------------------------------


def _normalize_symbol(raw: str) -> str:
    """Upper-case and strip trailing punctuation."""
    return raw.upper().rstrip(".,;:")


def _extract_symbols(speech_text: str) -> set[str]:
    """Return all normalized resolution symbol strings found in the text."""
    found: set[str] = set()

    # 1. Explicit draft symbols (highest priority — most specific)
    for m in _DRAFT_SYMBOL_RE.finditer(speech_text):
        found.add(_normalize_symbol(m.group(1)))

    # 2. Explicit adopted symbols with prefix
    for m in _ADOPTED_FULL_RE.finditer(speech_text):
        found.add(_normalize_symbol(m.group(1)))

    # 3. Natural-language GA: "resolution 64/299" → stored as "64/299"
    #    (lookup will try both "64/299" and "A/RES/64/299")
    for m in _GA_TEXT_RE.finditer(speech_text):
        sym = _normalize_symbol(m.group(1))
        # Skip if it looks like an SC resolution already captured above
        if "/" in sym:
            found.add(sym)

    # 4. Natural-language SC: "resolution 1441" → stored as "S/RES/1441"
    for m in _SC_TEXT_RE.finditer(speech_text):
        try:
            num = int(m.group(1))
        except ValueError:
            continue
        if num < _MIN_SC_RES_NUM:
            continue
        # Don't add if already matched by GA pattern (slash present)
        sym = f"S/RES/{num}"
        found.add(sym)

    return found


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def _ensure_schema(session: Session) -> None:
    session.execute(text("""
            CREATE TABLE IF NOT EXISTS speech_resolution_mentions (
                id            SERIAL  PRIMARY KEY,
                speech_id     INTEGER NOT NULL
                              REFERENCES speeches(id) ON DELETE CASCADE,
                cited_symbol  TEXT    NOT NULL,
                resolution_id INTEGER
                              REFERENCES resolutions(id) ON DELETE SET NULL,
                UNIQUE (speech_id, cited_symbol)
            )
            """))
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_srm_speech "
            "ON speech_resolution_mentions (speech_id)"
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_srm_resolution "
            "ON speech_resolution_mentions (resolution_id)"
        )
    )
    session.commit()


# ---------------------------------------------------------------------------
# Symbol → resolution_id index  (mirrors import_crUnsc_citations._build_symbol_index)
# ---------------------------------------------------------------------------


def _build_symbol_index(session: Session) -> dict[str, int]:
    """Return {symbol_variant: resolution_id} covering draft and adopted symbols."""
    rows = session.query(
        Resolution.id,
        Resolution.draft_symbol,
        Resolution.adopted_symbol,
        Resolution.body,
    ).all()
    idx: dict[str, int] = {}

    def _add(sym: str, res_id: int) -> None:
        s = sym.upper()
        if s and s not in idx:
            idx[s] = res_id

    for res_id, draft_sym, adopted_sym, body in rows:
        if draft_sym:
            _add(draft_sym, res_id)
        if adopted_sym:
            _add(adopted_sym, res_id)
            if body == "SC":
                # "S/RES/1441(2002)" → also index as "S/RES/1441"
                plain = adopted_sym.split("(")[0].strip()
                _add(plain, res_id)
            elif body == "GA":
                # "64/299" → also index as "A/RES/64/299"
                s = adopted_sym.upper()
                if not s.startswith("A/"):
                    _add(f"A/RES/{adopted_sym}", res_id)
                # And reverse: "A/RES/64/299" → also index "64/299"
                if s.startswith("A/RES/"):
                    _add(s[len("A/RES/") :], res_id)

    return idx


def _lookup(symbol: str, idx: dict[str, int]) -> int | None:
    """Return resolution_id for a symbol, trying common variants."""
    s = symbol.upper()
    if s in idx:
        return idx[s]
    # Strip trailing year parenthetical for SC: "S/RES/1441(2002)" → "S/RES/1441"
    plain = s.split("(")[0].strip()
    if plain in idx:
        return idx[plain]
    # Natural-language GA without prefix: "64/299" → "A/RES/64/299"
    if "/" in s and not s.startswith("A/") and not s.startswith("S/"):
        return idx.get(f"A/RES/{s}")
    # Full GA prefix → try without: "A/RES/64/299" → "64/299"
    if s.startswith("A/RES/"):
        return idx.get(s[len("A/RES/"):])
    return None


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------


def _upsert_mention(
    session: Session,
    speech_id: int,
    cited_symbol: str,
    resolution_id: int | None,
    dry_run: bool,
) -> bool:
    """Insert or update a mention row; return True if a row was written."""
    if dry_run:
        return True
    from sqlalchemy.engine import CursorResult

    result: CursorResult[Any] = session.execute(
        text("""
            INSERT INTO speech_resolution_mentions (speech_id, cited_symbol, resolution_id)
            VALUES (:sid, :sym, :rid)
            ON CONFLICT (speech_id, cited_symbol)
            DO UPDATE SET resolution_id = COALESCE(
                EXCLUDED.resolution_id,
                speech_resolution_mentions.resolution_id
            )
            """),
        {"sid": speech_id, "sym": cited_symbol, "rid": resolution_id},
    )
    return (result.rowcount or 0) > 0


def run_extraction(
    session: Session,
    body: str | None = None,
    dry_run: bool = False,
) -> tuple[int, int]:
    """Scan speeches and upsert mention rows.

    Returns (speeches_scanned, rows_written).
    """
    _ensure_schema(session)
    symbol_idx = _build_symbol_index(session)
    log.info("Symbol index built: %d entries", len(symbol_idx))

    conditions = ["1=1"]
    params: dict[str, object] = {}
    if body:
        conditions.append("d.body = :body")
        params["body"] = body.upper()

    where = " AND ".join(conditions)
    rows = session.execute(
        text(f"""
            SELECT sp.id, sp.text
            FROM speeches sp
            JOIN documents d ON d.id = sp.document_id
            WHERE {where}
            ORDER BY sp.id
            """),
        params,
    ).fetchall()

    log.info("Scanning %d speeches …", len(rows))

    total_written = 0
    batch_size = 1000

    for i, (speech_id, speech_text) in enumerate(rows):
        symbols = _extract_symbols(speech_text)
        for sym in symbols:
            res_id = _lookup(sym, symbol_idx)
            if _upsert_mention(session, speech_id, sym, res_id, dry_run):
                total_written += 1

        if not dry_run and (i + 1) % batch_size == 0:
            session.flush()
            log.info("  … %d/%d speeches processed", i + 1, len(rows))

    if not dry_run:
        session.commit()

    return len(rows), total_written


def run_backfill(session: Session, dry_run: bool = False) -> int:
    """Fill in NULL resolution_id FK for rows whose cited_symbol is now in the DB.

    Returns the number of rows updated.
    """
    symbol_idx = _build_symbol_index(session)
    rows = session.execute(
        text(
            "SELECT id, cited_symbol FROM speech_resolution_mentions "
            "WHERE resolution_id IS NULL"
        )
    ).fetchall()

    updated = 0
    for row_id, cited_symbol in rows:
        res_id = _lookup(cited_symbol, symbol_idx)
        if res_id is not None:
            if not dry_run:
                session.execute(
                    text(
                        "UPDATE speech_resolution_mentions "
                        "SET resolution_id = :rid WHERE id = :id"
                    ),
                    {"rid": res_id, "id": row_id},
                )
            updated += 1

    if not dry_run:
        session.commit()

    return updated


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Extract resolution symbol mentions from speech text.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument(
        "--body", default=None, choices=["GA", "SC"], help="Restrict to GA or SC"
    )
    p.add_argument(
        "--backfill-only",
        action="store_true",
        help="Only back-fill NULL resolution_id FKs; skip extraction pass",
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
        if not args.backfill_only:
            scanned, written = run_extraction(
                session, body=args.body, dry_run=args.dry_run
            )
            action = "Would write" if args.dry_run else "Wrote"
            log.info("%s %d mention rows from %d speeches", action, written, scanned)

        if not args.dry_run or args.backfill_only:
            updated = run_backfill(session, dry_run=args.dry_run)
            action = "Would update" if args.dry_run else "Updated"
            log.info("%s %d NULL resolution_id FKs via backfill", action, updated)

    return 0


if __name__ == "__main__":
    sys.exit(main())
