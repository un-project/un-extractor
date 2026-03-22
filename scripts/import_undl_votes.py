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
    # Allow optional dot and space: DHL has 'A/34/PV. 4' and 'S/PV9261'
    m = re.search(r"PV\.?\s*(\d+)", symbol, re.IGNORECASE)
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


def _ensure_columns(session: Session) -> None:
    """Add new columns to existing tables if missing (idempotent)."""
    migrations: list[tuple[str, str, str]] = [
        # resolutions
        ("resolutions", "agenda_title", "TEXT"),
        ("resolutions", "committee_report", "TEXT"),
        # votes
        ("votes", "total_non_voting", "INTEGER"),
        ("votes", "total_ms", "INTEGER"),
        ("votes", "vote_note", "TEXT"),
        ("votes", "undl_id", "VARCHAR(20)"),
        ("votes", "undl_link", "VARCHAR(500)"),
        # country_votes
        ("country_votes", "permanent_member", "BOOLEAN"),
    ]
    changed = False
    for table, column, col_type in migrations:
        exists = session.execute(
            text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name = :t AND column_name = :c"
            ),
            {"t": table, "c": column},
        ).fetchone()
        if exists is None:
            log.info("Adding column %s.%s …", table, column)
            session.execute(
                text(
                    f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS"
                    f" {column} {col_type}"
                )
            )
            changed = True
    # Widen VARCHAR columns to TEXT where data may exceed original limits
    for _tbl, _col in [
        ("resolutions", "category"),
        ("resolutions", "draft_symbol"),
        ("resolutions", "adopted_symbol"),
        ("resolutions", "committee_report"),
    ]:
        _col_info = session.execute(
            text(
                "SELECT data_type FROM information_schema.columns "
                "WHERE table_name = :t AND column_name = :c"
            ),
            {"t": _tbl, "c": _col},
        ).fetchone()
        if _col_info and _col_info[0].lower() != "text":
            log.info("Widening %s.%s to TEXT …", _tbl, _col)
            session.execute(text(f"ALTER TABLE {_tbl} ALTER COLUMN {_col} TYPE TEXT"))
            changed = True
    if changed:
        session.commit()


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
    subjects: str | None,
    agenda_title: str | None,
    committee_report: str | None,
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
                category=subjects,
                agenda_title=agenda_title,
                committee_report=committee_report,
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
    if subjects and not res.category:
        res.category = subjects
        changed = True
    if agenda_title and not res.agenda_title:
        res.agenda_title = agenda_title
        changed = True
    if committee_report and not res.committee_report:
        res.committee_report = committee_report
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
    total_non_voting: int | None,
    total_ms: int | None,
    vote_type: str,
    vote_note: str | None,
    undl_id: str | None,
    undl_link: str | None,
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
            total_non_voting=total_non_voting,
            total_ms=total_ms,
            vote_note=vote_note,
            undl_id=undl_id,
            undl_link=undl_link,
        )
        session.add(vote)
        session.flush()
    else:
        # Update counts and metadata from authoritative DHL data if they differ
        updated = False
        for attr, val in [
            ("yes_count", yes_count),
            ("no_count", no_count),
            ("abstain_count", abstain_count),
            ("total_non_voting", total_non_voting),
            ("total_ms", total_ms),
            ("vote_note", vote_note),
            ("undl_id", undl_id),
            ("undl_link", undl_link),
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
    permanent_member: bool | None,
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
                permanent_member=permanent_member,
            )
        )
    else:
        if existing.vote_position != vote_position:
            existing.vote_position = vote_position
        if (
            permanent_member is not None
            and existing.permanent_member != permanent_member
        ):  # noqa: E501
            existing.permanent_member = permanent_member


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
        # draft may be pipe-separated (e.g. A/58/L.25|A/58/L.25/Add.1); take first
        draft_symbol = first.get("draft", "").strip().split("|")[0].strip()
        vote_date = _parse_date(first.get("date", "").strip())
        title = (first.get("title") or first.get("description") or "").strip() or None
        subjects = first.get("subjects", "").strip() or None
        agenda_title = (
            first.get("agenda_title") or first.get("agenda") or ""
        ).strip() or None
        committee_report = first.get("committee_report", "").strip() or None
        vote_note = first.get("vote_note", "").strip() or None
        undl_link = first.get("undl_link", "").strip() or None

        yes_count = _int_or_none(first.get("total_yes", ""))
        no_count = _int_or_none(first.get("total_no", ""))
        abstain_count = _int_or_none(first.get("total_abstentions", ""))
        total_non_voting = _int_or_none(first.get("total_non_voting", ""))
        total_ms = _int_or_none(first.get("total_ms", ""))
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
                    subjects,
                    agenda_title,
                    committee_report,
                    res_cache,
                )

                vote = _get_or_create_vote(
                    session,
                    doc,
                    resolution,
                    yes_count,
                    no_count,
                    abstain_count,
                    total_non_voting,
                    total_ms,
                    vote_type,
                    vote_note,
                    undl_id,
                    undl_link,
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
                    pm_raw = row.get("permanent_member", "").strip().lower()
                    if pm_raw == "true":
                        permanent_member: bool | None = True
                    elif pm_raw == "false":
                        permanent_member = False
                    else:
                        permanent_member = None

                    country = _get_or_create_country_by_code(
                        session, ms_code, ms_name, country_cache
                    )
                    if country:
                        _upsert_country_vote(
                            session, vote, country, vote_position, permanent_member
                        )
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
        _ensure_columns(session)

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
