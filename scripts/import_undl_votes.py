#!/usr/bin/env python3
"""Import UN Digital Library official voting datasets (GA + SC) into the DB.

Downloads the authoritative CSV files published by the Dag Hammarskjöld
Library and upserts them into the existing schema.  Running the script
multiple times is safe (idempotent).

Data sources
------------
  GA: https://digitallibrary.un.org/record/4060887/files/2026_02_06_ga_voting.csv
  SC: https://digitallibrary.un.org/record/4055387/files/2026_02_06_sc_voting.csv

Each CSV row represents one Member State's vote on one resolution.
Rows are grouped by ``undl_id`` (unique per resolution-vote event).

Mapping to DB schema
--------------------
  meeting   → documents.symbol      (stub document created if not yet extracted)
  draft     → resolutions.draft_symbol
  resolution→ resolutions.adopted_symbol
  ms_code   → countries.iso3
  ms_vote   → country_votes.vote_position  (Y→yes, N→no, A→abstain, X→non_voting)

Usage
-----
    python scripts/import_undl_votes.py
    python scripts/import_undl_votes.py --download          # force fresh download
    python scripts/import_undl_votes.py --ga-csv path.csv --sc-csv path.csv
    python scripts/import_undl_votes.py --dry-run
    python scripts/import_undl_votes.py --db postgresql://user:pass@host/db
"""

from __future__ import annotations

import argparse
import csv
import logging
import re
import sys
import urllib.request
from datetime import date
from itertools import groupby
from operator import itemgetter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402
from src.db.models import Country, Document, Resolution, Vote, CountryVote  # noqa: E402
from src.extraction.country_aliases import normalize_country_name  # noqa: E402

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Official DHL download URLs (update when new versions are published)
# ---------------------------------------------------------------------------

GA_URL = (
    "https://digitallibrary.un.org/record/4060887" "/files/2026_02_06_ga_voting.csv"
)
SC_URL = (
    "https://digitallibrary.un.org/record/4055387" "/files/2026_02_06_sc_voting.csv"
)

_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "undl"

# ---------------------------------------------------------------------------
# Vote position mapping  (DHL code → DB enum value)
# ---------------------------------------------------------------------------

_VOTE_MAP: dict[str, str] = {
    "Y": "yes",
    "N": "no",
    "A": "abstain",
    "X": "non_voting",
}

# ---------------------------------------------------------------------------
# Meeting symbol helpers
# ---------------------------------------------------------------------------

_GA_MEETING_RE = re.compile(r"A/\d+/PV\.\d+", re.IGNORECASE)
_SC_MEETING_RE = re.compile(r"S/PV\.\d+", re.IGNORECASE)


def _parse_meeting_number(symbol: str) -> int | None:
    m = re.search(r"PV\.(\d+)", symbol, re.IGNORECASE)
    return int(m.group(1)) if m else None


def _parse_session(symbol: str) -> int | None:
    # Regular GA session: A/64/PV.121 → 64
    m = re.search(r"[AS]/(\d+)/PV\.", symbol, re.IGNORECASE)
    if m:
        return int(m.group(1))
    # Emergency Special Session: A/ES-10/PV.37 → no regular session number
    return None


def _parse_body(symbol: str) -> str:
    return "SC" if symbol.upper().startswith("S/") else "GA"


def _parse_date(date_str: str) -> date | None:
    if not date_str:
        return None
    try:
        return date.fromisoformat(date_str)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Schema migration helper
# ---------------------------------------------------------------------------


def _ensure_non_voting_enum(session: Session) -> None:
    """Add ``non_voting`` to vote_position_enum if missing (idempotent)."""
    result = session.execute(
        text(
            "SELECT 1 FROM pg_enum "
            "JOIN pg_type ON pg_type.oid = pg_enum.enumtypid "
            "WHERE pg_type.typname = 'vote_position_enum' "
            "AND pg_enum.enumlabel = 'non_voting'"
        )
    ).fetchone()
    if result is None:
        log.info("Adding 'non_voting' to vote_position_enum …")
        session.execute(text("ALTER TYPE vote_position_enum ADD VALUE 'non_voting'"))
        # ALTER TYPE needs to commit before it is visible to subsequent DML.
        session.commit()
        log.info("Enum updated.")


def _ensure_session_nullable(session: Session) -> None:
    """Drop NOT NULL on documents.session if it exists (idempotent).

    Emergency Special Session symbols (A/ES-10/PV.37) have no parseable
    GA session number, so the column must allow NULL.
    """
    result = session.execute(
        text(
            "SELECT is_nullable FROM information_schema.columns "
            "WHERE table_name = 'documents' AND column_name = 'session'"
        )
    ).fetchone()
    if result and result[0] == "NO":
        log.info("Dropping NOT NULL constraint on documents.session …")
        session.execute(
            text("ALTER TABLE documents ALTER COLUMN session DROP NOT NULL")
        )
        session.commit()
        log.info("Column updated.")


# ---------------------------------------------------------------------------
# Download helper
# ---------------------------------------------------------------------------


def _download(url: str, dest: Path, force: bool = False) -> Path:
    if dest.exists() and not force:
        log.info("Using cached %s", dest.name)
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    log.info("Downloading %s …", url)
    req = urllib.request.Request(url, headers={"User-Agent": "un-extractor/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        dest.write_bytes(resp.read())
    log.info("Saved to %s (%d bytes)", dest, dest.stat().st_size)
    return dest


# ---------------------------------------------------------------------------
# Lookup / upsert helpers
# ---------------------------------------------------------------------------


def _get_or_create_country_by_code(
    session: Session,
    ms_code: str,
    ms_name: str,
    _cache: dict[str, Country],
) -> Country | None:
    """Resolve a country by ISO-3 code; fall back to name normalisation."""
    if ms_code in _cache:
        return _cache[ms_code]

    country = session.query(Country).filter_by(iso3=ms_code).first()
    if country is None:
        # Fallback: try normalised name
        canonical = normalize_country_name(ms_name)
        country = session.query(Country).filter_by(name=canonical).first()
    if country is None:
        # Last resort: create a minimal row so no vote data is lost
        canonical = normalize_country_name(ms_name) or ms_name
        country = Country(name=canonical, iso3=ms_code)
        session.add(country)
        session.flush()
        log.debug("Created country %r (iso3=%s)", canonical, ms_code)

    _cache[ms_code] = country
    return country


def _get_or_create_document(
    session: Session,
    meeting_symbol: str,
    vote_date: date | None,
    body: str,
    _cache: dict[str, Document],
) -> Document | None:
    if not meeting_symbol:
        return None
    if meeting_symbol in _cache:
        return _cache[meeting_symbol]

    doc = session.query(Document).filter_by(symbol=meeting_symbol).first()
    if doc is None:
        meeting_num = _parse_meeting_number(meeting_symbol)
        if meeting_num is None:
            log.warning("Cannot parse meeting number from %r", meeting_symbol)
            return None
        doc = Document(
            symbol=meeting_symbol,
            body=body,
            meeting_number=meeting_num,
            session=_parse_session(meeting_symbol),
            date=vote_date,
        )
        session.add(doc)
        session.flush()
        log.debug("Created stub document %s", meeting_symbol)

    _cache[meeting_symbol] = doc
    return doc


def _get_or_create_resolution(
    session: Session,
    draft_symbol: str,
    adopted_symbol: str,
    body: str,
    session_num: int | None,
    title: str | None,
    _cache: dict[str, Resolution],
) -> Resolution:
    key = draft_symbol or adopted_symbol
    res: Resolution | None = _cache.get(key)
    if res is None:
        if draft_symbol:
            res = session.query(Resolution).filter_by(draft_symbol=draft_symbol).first()
        if res is None and adopted_symbol:
            res = (
                session.query(Resolution)
                .filter_by(adopted_symbol=adopted_symbol)
                .first()
            )
        if res is None:
            res = Resolution(
                draft_symbol=draft_symbol or adopted_symbol,
                adopted_symbol=adopted_symbol or None,
                body=body,
                session=session_num,
                title=title,
            )
            session.add(res)
            session.flush()
            log.debug("Created resolution %r", key)
        _cache[key] = res

    # Backfill fields that may be missing from PDF extraction
    changed = False
    if adopted_symbol and not res.adopted_symbol:
        res.adopted_symbol = adopted_symbol
        changed = True
    if draft_symbol and res.draft_symbol != draft_symbol:
        # Prefer the explicit draft symbol over the adopted symbol used as key
        if res.draft_symbol == res.adopted_symbol:
            res.draft_symbol = draft_symbol
            changed = True
    if title and not res.title:
        res.title = title
        changed = True
    if changed:
        session.flush()

    return res


def _get_or_create_vote(
    session: Session,
    doc: Document,
    resolution: Resolution,
    yes_count: int | None,
    no_count: int | None,
    abstain_count: int | None,
    vote_type: str,
    _cache: dict[tuple[int, int], Vote],
) -> Vote:
    cache_key = (doc.id, resolution.id)
    if cache_key in _cache:
        return _cache[cache_key]

    vote = (
        session.query(Vote)
        .filter_by(document_id=doc.id, resolution_id=resolution.id)
        .first()
    )
    if vote is None:
        vote = Vote(
            document_id=doc.id,
            resolution_id=resolution.id,
            vote_type=vote_type,
            vote_scope="whole_resolution",
            yes_count=yes_count,
            no_count=no_count,
            abstain_count=abstain_count,
        )
        session.add(vote)
        session.flush()
    else:
        # Update counts from authoritative DHL data if they differ
        updated = False
        for attr, val in [
            ("yes_count", yes_count),
            ("no_count", no_count),
            ("abstain_count", abstain_count),
        ]:
            if val is not None and getattr(vote, attr) != val:
                setattr(vote, attr, val)
                updated = True
        if updated:
            session.flush()

    _cache[cache_key] = vote
    return vote


def _upsert_country_vote(
    session: Session,
    vote: Vote,
    country: Country,
    vote_position: str,
) -> None:
    existing = (
        session.query(CountryVote)
        .filter_by(vote_id=vote.id, country_id=country.id)
        .first()
    )
    if existing is None:
        session.add(
            CountryVote(
                vote_id=vote.id,
                country_id=country.id,
                vote_position=vote_position,
            )
        )
    elif existing.vote_position != vote_position:
        existing.vote_position = vote_position


# ---------------------------------------------------------------------------
# CSV importer
# ---------------------------------------------------------------------------


def _int_or_none(val: str) -> int | None:
    val = val.strip()
    return int(val) if val.isdigit() else None


def import_csv(
    session: Session,
    csv_path: Path,
    body: str,
    dry_run: bool = False,
    batch_size: int = 500,
) -> tuple[int, int]:
    """Import one DHL CSV file.  Returns (resolutions_processed, rows_processed)."""
    country_cache: dict[str, Country] = {}
    doc_cache: dict[str, Document] = {}
    res_cache: dict[str, Resolution] = {}
    vote_cache: dict[tuple[int, int], Vote] = {}

    resolutions_done = 0
    rows_done = 0

    with csv_path.open(encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)

    log.info("Processing %d rows from %s …", len(rows), csv_path.name)

    # Group by undl_id so we process one resolution event at a time
    rows.sort(key=itemgetter("undl_id"))
    for undl_id, group_iter in groupby(rows, key=itemgetter("undl_id")):
        group = list(group_iter)
        first = group[0]

        meeting_symbol = first.get("meeting", "").strip()
        adopted_symbol = first.get("resolution", "").strip()
        draft_symbol = first.get("draft", "").strip()
        vote_date = _parse_date(first.get("date", "").strip())
        title = (first.get("title") or first.get("description") or "").strip() or None

        yes_count = _int_or_none(first.get("total_yes", ""))
        no_count = _int_or_none(first.get("total_no", ""))
        abstain_count = _int_or_none(first.get("total_abstentions", ""))
        session_num = _int_or_none(first.get("session", ""))

        # Determine vote type: SC has 'modality', GA is always recorded
        modality = first.get("modality", "").strip().lower()
        if modality in ("without a vote", "without vote", "acclamation"):
            vote_type = "consensus"
        else:
            vote_type = "recorded"

        if not meeting_symbol:
            log.debug("Skipping undl_id=%s: no meeting symbol", undl_id)
            continue

        if not dry_run:
            with session.begin_nested():
                doc = _get_or_create_document(
                    session, meeting_symbol, vote_date, body, doc_cache
                )
                if doc is None:
                    continue

                resolution = _get_or_create_resolution(
                    session,
                    draft_symbol,
                    adopted_symbol,
                    body,
                    session_num,
                    title,
                    res_cache,
                )

                vote = _get_or_create_vote(
                    session,
                    doc,
                    resolution,
                    yes_count,
                    no_count,
                    abstain_count,
                    vote_type,
                    vote_cache,
                )

                for row in group:
                    ms_code = row.get("ms_code", "").strip()
                    ms_name = row.get("ms_name", "").strip()
                    ms_vote_raw = row.get("ms_vote", "").strip().upper()
                    vote_position = _VOTE_MAP.get(ms_vote_raw)
                    if vote_position is None:
                        log.debug("Unknown vote code %r for %s", ms_vote_raw, ms_code)
                        continue

                    country = _get_or_create_country_by_code(
                        session, ms_code, ms_name, country_cache
                    )
                    if country:
                        _upsert_country_vote(session, vote, country, vote_position)
                    rows_done += 1

        resolutions_done += 1

        if resolutions_done % batch_size == 0:
            if not dry_run:
                session.flush()
            log.info("  … %d resolutions processed", resolutions_done)

    return resolutions_done, rows_done


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run(
    db_url: str | None = None,
    ga_csv: Path | None = None,
    sc_csv: Path | None = None,
    download: bool = False,
    dry_run: bool = False,
) -> None:
    if ga_csv is None:
        ga_csv = _download(GA_URL, _DATA_DIR / "ga_voting.csv", force=download)
    if sc_csv is None:
        sc_csv = _download(SC_URL, _DATA_DIR / "sc_voting.csv", force=download)

    engine = get_engine(db_url)
    create_schema(engine)

    # Schema migrations (each needs its own commit before DML proceeds)
    with get_session(engine) as session:
        _ensure_non_voting_enum(session)
        _ensure_session_nullable(session)

    with get_session(engine) as session:
        log.info("=== Importing GA voting data ===")
        ga_res, ga_rows = import_csv(session, ga_csv, "GA", dry_run=dry_run)
        log.info("GA: %d resolutions, %d country-vote rows", ga_res, ga_rows)

        log.info("=== Importing SC voting data ===")
        sc_res, sc_rows = import_csv(session, sc_csv, "SC", dry_run=dry_run)
        log.info("SC: %d resolutions, %d country-vote rows", sc_res, sc_rows)

    if dry_run:
        log.info("Dry run — no changes committed.")
    else:
        log.info(
            "Done. Total: %d resolutions, %d country-vote rows.",
            ga_res + sc_res,
            ga_rows + sc_rows,
        )


def main() -> int:
    p = argparse.ArgumentParser(
        description="Import UN Digital Library official voting CSVs into the DB.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument(
        "--ga-csv",
        type=Path,
        default=None,
        help="Path to local GA voting CSV (skips download)",
    )
    p.add_argument(
        "--sc-csv",
        type=Path,
        default=None,
        help="Path to local SC voting CSV (skips download)",
    )
    p.add_argument(
        "--download",
        action="store_true",
        help="Force re-download even if cached files exist",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and log without writing to the database",
    )
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    run(
        db_url=args.db,
        ga_csv=args.ga_csv,
        sc_csv=args.sc_csv,
        download=args.download,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
