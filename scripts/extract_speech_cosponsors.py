#!/usr/bin/env python3
"""Extract co-sponsorship mentions from speech text and populate resolution_sponsors.

Scans ``speeches.text`` for co-sponsorship patterns and inserts
``(resolution_id, country_id, country_name)`` rows into ``resolution_sponsors``.

Coverage
--------
- GA resolutions (all periods)
- SC resolutions pre-1994 (post-1994 SC already imported by import_unbench_sc_drafts.py)

The script is safe to re-run: all inserts use ``ON CONFLICT DO NOTHING``.

Patterns handled
----------------
1. **Explicit list** —
   "The following [N] countries are co-sponsors of draft resolution A/64/L.72: …"
   Comma-separated country list terminated by end-of-line or "." / ";".

2. **Single-country with symbol** —
   "co-sponsor[ed/s] … draft resolution A/64/L.72"
   or "[delegation] co-sponsored draft resolution A/64/L.72 (A/64/L.72)"
   Country inferred from the speech's speaker.

3. **Implicit single-country** —
   "we are pleased to co-sponsor [the draft resolution]" (no explicit symbol)
   Symbol resolved via ``votes WHERE item_id = speech.item_id``.

Usage
-----
    python scripts/extract_speech_cosponsors.py
    python scripts/extract_speech_cosponsors.py --db postgresql://...
    python scripts/extract_speech_cosponsors.py --dry-run
    python scripts/extract_speech_cosponsors.py --verbose
    python scripts/extract_speech_cosponsors.py --body GA
    python scripts/extract_speech_cosponsors.py --body SC --before-year 1994
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
from src.extraction.country_aliases import normalize_country_name  # noqa: E402

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Draft resolution symbol, e.g. A/64/L.72, S/2023/970, A/C.3/78/L.5
_SYMBOL_RE = re.compile(
    r"\b([A-Z](?:[A-Z0-9/.-]*L\.[0-9]+(?:/Rev\.[0-9]+)?|"
    r"[A-Z0-9/.-]*(?:RES|DEC)/[0-9]+(?:/[0-9]+)?|"
    r"[0-9]{4}/[0-9]+))\b",
    re.IGNORECASE,
)

# "The following [N] countries [are|were|have become] co-sponsors[/co-sponsors] of
#  draft resolution SYMBOL[:] list…"
_LIST_PATTERN = re.compile(
    r"following\s+(?:\w+\s+)?(?:countries|delegations|states|members)\s+"
    r"(?:are|were|have\s+become|are\s+now|also\s+become)?\s*"
    r"co[\-\s]?sponsors?\s+of\s+(?:draft\s+)?resolution\s+"
    r"([A-Z][A-Z0-9/.\-]+)\s*[:\-]?\s*"
    r"((?:[A-Z][a-zA-Z\s\-'()]+(?:,\s*)?)+)",
    re.IGNORECASE,
)

# Single co-sponsor with explicit symbol:
# "[delegation/country] co-sponsor[s/ed] [the] draft resolution SYMBOL"
# or "pleased to co-sponsor … (SYMBOL)"
_SINGLE_SYMBOL_RE = re.compile(
    r"co[\-\s]?sponsor(?:s|ed|ing)?\b(?:\s+\w+){0,6}?"
    r"\s+(?:draft\s+)?resolution\s+([A-Z][A-Z0-9/.\-]+)",
    re.IGNORECASE,
)

# Parenthetical symbol after co-sponsor mention:
# "co-sponsor[s/ed] … (A/79/L.8)"
_PAREN_SYMBOL_RE = re.compile(
    r"co[\-\s]?sponsor(?:s|ed|ing)?\b.{0,120}?"
    r"\(([A-Z][A-Z0-9/.\-]+(?:L\.[0-9]+|RES/[0-9]+)[A-Z0-9/.\-]*)\)",
    re.IGNORECASE,
)

# Implicit: no symbol in sentence but "co-sponsor" appears
_IMPLICIT_RE = re.compile(r"\bco[\-\s]?sponsor", re.IGNORECASE)

# Negative guard — "co-sponsor of the peace process", "co-sponsor of this initiative"
# (these are not resolution co-sponsorships)
_NON_RES_RE = re.compile(
    r"co[\-\s]?sponsor\s+of\s+(?:the\s+)?(?:peace\s+process|initiative|"
    r"efforts?|talks?|negotiations?|meeting|conference|summit)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helper: extract symbol candidates from a sentence
# ---------------------------------------------------------------------------


def _looks_like_draft_symbol(sym: str) -> bool:
    """Return True if the symbol string looks like a draft resolution symbol."""
    s = sym.upper()
    # Must have at least one slash
    if "/" not in s:
        return False
    # Veto filters: generic short tokens that are not real symbols
    if re.fullmatch(r"[A-Z]{1,3}", s):
        return False
    # Must contain at least a digit
    if not any(c.isdigit() for c in s):
        return False
    return True


def _extract_symbols(text: str) -> list[str]:
    return [
        m.group(1)
        for m in _SYMBOL_RE.finditer(text)
        if _looks_like_draft_symbol(m.group(1))
    ]


# ---------------------------------------------------------------------------
# Helper: split a country list string
# ---------------------------------------------------------------------------

_LIST_TERMINATORS = re.compile(
    r"[.;]|\band\s+others\b|\beight\b|\bfollowing\b", re.IGNORECASE
)


def _parse_country_list(raw: str) -> list[str]:
    """Split a raw country list like 'Algeria, Angola, Argentina…' into names."""
    # Trim at first sentence terminator
    m = _LIST_TERMINATORS.search(raw)
    if m:
        raw = raw[: m.start()]
    parts = re.split(r",\s*(?:and\s+)?", raw.strip())
    names = []
    for part in parts:
        name = normalize_country_name(part.strip())
        if name and len(name) > 1:
            names.append(name)
    return names


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _ensure_schema(session: Session) -> None:
    """Create resolution_sponsors if not already present (idempotent)."""
    session.execute(text("""
            CREATE TABLE IF NOT EXISTS resolution_sponsors (
                id            SERIAL PRIMARY KEY,
                resolution_id INTEGER NOT NULL
                              REFERENCES resolutions(id) ON DELETE CASCADE,
                country_id    INTEGER REFERENCES countries(id) ON DELETE SET NULL,
                country_name  TEXT NOT NULL,
                UNIQUE (resolution_id, country_name)
            )
            """))
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_res_sponsors_resolution "
            "ON resolution_sponsors (resolution_id)"
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_res_sponsors_country "
            "ON resolution_sponsors (country_id)"
        )
    )
    session.commit()


def _build_country_index(session: Session) -> dict[str, int]:
    """Return {canonical_name: country_id} for all known countries."""
    rows = session.execute(text("SELECT id, name FROM countries")).fetchall()
    return {normalize_country_name(r[1]) or r[1]: r[0] for r in rows}


def _resolve_country_id(name: str, index: dict[str, int]) -> int | None:
    canon = normalize_country_name(name)
    if canon:
        return index.get(canon)
    return None


def _resolve_symbol_to_resolution(
    symbol: str, session: Session, symbol_cache: dict[str, int | None]
) -> int | None:
    if symbol in symbol_cache:
        return symbol_cache[symbol]
    row = session.execute(
        text("SELECT id FROM resolutions WHERE draft_symbol = :s LIMIT 1"),
        {"s": symbol},
    ).first()
    res_id = row[0] if row else None
    # Also try adopted_symbol
    if res_id is None:
        row = session.execute(
            text("SELECT id FROM resolutions WHERE adopted_symbol = :s LIMIT 1"),
            {"s": symbol},
        ).first()
        res_id = row[0] if row else None
    symbol_cache[symbol] = res_id
    return res_id


def _item_resolutions(
    item_id: int, session: Session, item_cache: dict[int, list[int]]
) -> list[int]:
    if item_id in item_cache:
        return item_cache[item_id]
    rows = session.execute(
        text("SELECT resolution_id FROM votes WHERE item_id = :iid"),
        {"iid": item_id},
    ).fetchall()
    ids = [r[0] for r in rows]
    item_cache[item_id] = ids
    return ids


def _insert_sponsor(
    session: Session,
    resolution_id: int,
    country_name: str,
    country_id: int | None,
    dry_run: bool,
) -> bool:
    """Insert one sponsor row; return True if a new row would be inserted."""
    if dry_run:
        return True
    from sqlalchemy.engine import CursorResult

    result: CursorResult[Any] = session.execute(
        text("""
            INSERT INTO resolution_sponsors (resolution_id, country_id, country_name)
            VALUES (:rid, :cid, :name)
            ON CONFLICT (resolution_id, country_name) DO NOTHING
            """),
        {"rid": resolution_id, "cid": country_id, "name": country_name},
    )
    return (result.rowcount or 0) > 0


# ---------------------------------------------------------------------------
# Main extraction logic
# ---------------------------------------------------------------------------


def _process_speech(
    speech_id: int,
    speech_text: str,
    item_id: int | None,
    speaker_country: str | None,
    session: Session,
    country_index: dict[str, int],
    symbol_cache: dict[str, int | None],
    item_cache: dict[int, list[int]],
    dry_run: bool,
) -> int:
    """Process one speech; return count of new sponsor rows inserted."""
    inserted = 0

    # Quick pre-filter: must contain "co-sponsor" somewhere
    if not _IMPLICIT_RE.search(speech_text):
        return 0

    # Reject sentences about non-resolution co-sponsorships
    # Work sentence by sentence for better precision
    sentences = re.split(r"(?<=[.!?])\s+", speech_text)

    for sentence in sentences:
        if not _IMPLICIT_RE.search(sentence):
            continue
        if _NON_RES_RE.search(sentence):
            continue

        # Pattern 1: explicit country list
        m = _LIST_PATTERN.search(sentence)
        if m:
            raw_symbol = m.group(1).strip()
            raw_list = m.group(2).strip()
            if _looks_like_draft_symbol(raw_symbol):
                res_id = _resolve_symbol_to_resolution(
                    raw_symbol, session, symbol_cache
                )
                if res_id is not None:
                    for country_name in _parse_country_list(raw_list):
                        cid = _resolve_country_id(country_name, country_index)
                        if inserted == 0 or True:  # always try
                            if _insert_sponsor(
                                session, res_id, country_name, cid, dry_run
                            ):
                                inserted += 1
                                log.debug(
                                    "speech %d list co-sponsor: %s → %s",
                                    speech_id,
                                    country_name,
                                    raw_symbol,
                                )
            continue

        # Pattern 2a: "co-sponsor[s/ed] draft resolution SYMBOL"
        m2 = _SINGLE_SYMBOL_RE.search(sentence)
        symbol = m2.group(1).strip() if m2 else None

        # Pattern 2b: parenthetical symbol
        if symbol is None:
            m3 = _PAREN_SYMBOL_RE.search(sentence)
            symbol = m3.group(1).strip() if m3 else None

        if symbol and _looks_like_draft_symbol(symbol):
            res_id = _resolve_symbol_to_resolution(symbol, session, symbol_cache)
            if res_id is not None and speaker_country:
                canon = normalize_country_name(speaker_country)
                if canon:
                    cid = country_index.get(canon)
                    if _insert_sponsor(session, res_id, canon, cid, dry_run):
                        inserted += 1
                        log.debug(
                            "speech %d single co-sponsor: %s → %s",
                            speech_id,
                            canon,
                            symbol,
                        )
            continue

        # Pattern 3: implicit — no symbol, resolve from item votes
        if item_id is not None and speaker_country:
            res_ids = _item_resolutions(item_id, session, item_cache)
            if len(res_ids) == 1:
                canon = normalize_country_name(speaker_country)
                if canon:
                    cid = country_index.get(canon)
                    if _insert_sponsor(session, res_ids[0], canon, cid, dry_run):
                        inserted += 1
                        log.debug(
                            "speech %d implicit co-sponsor: %s (item %d → res %d)",
                            speech_id,
                            canon,
                            item_id,
                            res_ids[0],
                        )
            elif len(res_ids) > 1:
                log.debug(
                    "speech %d: implicit co-sponsor but item %d has %d resolutions — skipping",
                    speech_id,
                    item_id,
                    len(res_ids),
                )

    return inserted


def run(
    session: Session,
    body: str | None = None,
    before_year: int | None = None,
    dry_run: bool = False,
) -> tuple[int, int]:
    """Scan speeches and insert co-sponsorship rows.

    Returns (speeches_scanned, sponsors_inserted).
    """
    _ensure_schema(session)

    country_index = _build_country_index(session)
    log.info("Loaded %d countries into index", len(country_index))

    # Build WHERE clause
    conditions = ["sp.text ILIKE '%co-sponsor%'"]
    params: dict[str, object] = {}
    if body:
        conditions.append("d.body = :body")
        params["body"] = body.upper()
    if before_year is not None:
        conditions.append(
            "(d.date IS NULL OR EXTRACT(YEAR FROM d.date) < :before_year)"
        )
        params["before_year"] = before_year

    where = " AND ".join(conditions)

    query = text(f"""
        SELECT
            sp.id,
            sp.text,
            sp.item_id,
            c.name AS country_name
        FROM speeches sp
        JOIN documents d ON d.id = sp.document_id
        LEFT JOIN speakers sk ON sk.id = sp.speaker_id
        LEFT JOIN countries c ON c.id = sk.country_id
        WHERE {where}
        ORDER BY sp.id
        """)

    rows = session.execute(query, params).fetchall()
    log.info("Found %d candidate speeches", len(rows))

    symbol_cache: dict[str, int | None] = {}
    item_cache: dict[int, list[int]] = {}
    total_inserted = 0

    for speech_id, speech_text, item_id, country_name in rows:
        n = _process_speech(
            speech_id=speech_id,
            speech_text=speech_text,
            item_id=item_id,
            speaker_country=country_name,
            session=session,
            country_index=country_index,
            symbol_cache=symbol_cache,
            item_cache=item_cache,
            dry_run=dry_run,
        )
        total_inserted += n

    if not dry_run:
        session.commit()

    return len(rows), total_inserted


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Extract co-sponsorship mentions from speeches into resolution_sponsors.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--db", default=None, help="Database URL (overrides DATABASE_URL env var)"
    )
    p.add_argument(
        "--body", default=None, choices=["GA", "SC"], help="Restrict to GA or SC"
    )
    p.add_argument(
        "--before-year",
        type=int,
        default=None,
        help="Only process speeches from documents before this year (e.g. 1994 for pre-UNBench SC)",
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
        scanned, inserted = run(
            session,
            body=args.body,
            before_year=args.before_year,
            dry_run=args.dry_run,
        )

    action = "Would insert" if args.dry_run else "Inserted"
    log.info("%s %d co-sponsor rows from %d speeches", action, inserted, scanned)
    return 0


if __name__ == "__main__":
    sys.exit(main())
