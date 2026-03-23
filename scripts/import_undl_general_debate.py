#!/usr/bin/env python3
"""Import UN General Debate speeches metadata into the database.

Downloads the Dag Hammarskjöld Library's General Debate speeches dataset
(GA sessions 1–79, 1946–2024) and upserts it into two places:

1. Sets ``documents.is_general_debate = TRUE`` for each plenary meeting that
   contained a General Debate segment.
2. Populates a new ``general_debate_entries`` table with one row per speaker,
   linking to the country, document, and (when matchable) the speaker row, and
   storing the UNDL link to the individual speech document.

Data source
-----------
  Dag Hammarskjöld Library (2026).  United Nations General Assembly General
  Debate Speeches Dataset (Version 3).
  https://digitallibrary.un.org/record/4067189

CSV columns
-----------
  Name, Salutation, Member State, GA Session, Meeting Date,
  Meeting Symbol, Agenda Items, UNDL ID, UNDL Link

Usage
-----
    python scripts/import_undl_general_debate.py
    python scripts/import_undl_general_debate.py --db postgresql://user:pass@host/db
    python scripts/import_undl_general_debate.py --csv path/to/file.csv
    python scripts/import_undl_general_debate.py --download
    python scripts/import_undl_general_debate.py --dry-run
    python scripts/import_undl_general_debate.py --verbose
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
import urllib.request
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402
from src.db.models import Country, Document, Speaker  # noqa: E402
from src.extraction.country_aliases import normalize_country_name  # noqa: E402

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Download URL (update when a new version is published)
# ---------------------------------------------------------------------------

_CSV_URL = (
    "https://digitallibrary.un.org/record/4067189/files"
    "/GA_debate_speech_dataset_20260129.csv"
)

_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "undl"

# ---------------------------------------------------------------------------
# Schema migration
# ---------------------------------------------------------------------------


def _ensure_schema(session: Session) -> None:
    """Add is_general_debate column and general_debate_entries table if missing."""
    # documents.is_general_debate
    exists = session.execute(
        text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = 'documents' AND column_name = 'is_general_debate'"
        )
    ).fetchone()
    if exists is None:
        log.info("Adding column documents.is_general_debate …")
        session.execute(
            text(
                "ALTER TABLE documents "
                "ADD COLUMN IF NOT EXISTS is_general_debate BOOLEAN NOT NULL DEFAULT FALSE"
            )
        )

    # general_debate_entries table
    session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS general_debate_entries (
                id              SERIAL      PRIMARY KEY,
                document_id     INTEGER
                                            REFERENCES documents(id)
                                            ON DELETE SET NULL,
                country_id      INTEGER
                                            REFERENCES countries(id)
                                            ON DELETE SET NULL,
                speaker_id      INTEGER
                                            REFERENCES speakers(id)
                                            ON DELETE SET NULL,
                speaker_name    TEXT        NOT NULL,
                salutation      VARCHAR(20),
                ga_session      INTEGER     NOT NULL,
                meeting_date    DATE,
                undl_id         VARCHAR(30),
                undl_link       TEXT,
                UNIQUE (ga_session, speaker_name, country_id)
            )
            """
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_gde_document "
            "ON general_debate_entries (document_id)"
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_gde_country "
            "ON general_debate_entries (country_id)"
        )
    )
    session.commit()


# ---------------------------------------------------------------------------
# Download helper
# ---------------------------------------------------------------------------


def _download(url: str, dest: Path, force: bool = False) -> Path:
    if dest.exists() and not force:
        log.info("Using cached %s", dest)
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    log.info("Downloading %s → %s …", url, dest)
    urllib.request.urlretrieve(url, dest)
    log.info("Downloaded %s (%.1f MB)", dest.name, dest.stat().st_size / 1e6)
    return dest


# ---------------------------------------------------------------------------
# Name normalisation
# ---------------------------------------------------------------------------


def _normalise_name(raw: str) -> str:
    """Convert 'Last, First' → 'First Last' for speaker lookup."""
    if "," in raw:
        last, _, first = raw.partition(",")
        return f"{first.strip()} {last.strip()}"
    return raw.strip()


def _parse_date(s: str) -> date | None:
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y"):
        try:
            from datetime import datetime
            return datetime.strptime(s.strip(), fmt).date()
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Main import logic
# ---------------------------------------------------------------------------


def _build_country_index(session: Session) -> dict[str, int]:
    """Return normalised_name → country_id for all countries."""
    rows = session.query(Country.id, Country.name).all()
    idx: dict[str, int] = {}
    for cid, name in rows:
        idx[normalize_country_name(name)] = cid
    return idx


def _find_speaker(
    session: Session,
    display_name: str,
    country_id: int | None,
) -> int | None:
    """Return speaker.id by partial name + country match, or None."""
    if country_id is None:
        return None
    # Try exact match first
    spk = (
        session.query(Speaker)
        .filter_by(country_id=country_id)
        .filter(Speaker.name == display_name)
        .first()
    )
    if spk:
        return spk.id
    # Try last-name suffix match (our speakers are stored as "Mr. LastName")
    last = display_name.split()[-1] if display_name else ""
    if last:
        spk = (
            session.query(Speaker)
            .filter_by(country_id=country_id)
            .filter(Speaker.name.ilike(f"%{last}%"))
            .first()
        )
        if spk:
            return spk.id
    return None


def _import_csv(
    session: Session,
    csv_path: Path,
    dry_run: bool,
) -> tuple[int, int, int]:
    """Parse the CSV and upsert into the DB.

    Returns (inserted, updated, skipped).
    """
    inserted = updated = skipped = 0

    country_idx = _build_country_index(session)

    # Pre-load document symbol → id map
    doc_rows = session.query(Document.id, Document.symbol).all()
    doc_idx: dict[str, int] = {sym: did for did, sym in doc_rows}

    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            raw_name = (row.get("Name") or "").strip()
            salutation = (row.get("Salutation") or "").strip() or None
            member_state = (row.get("Member State") or "").strip()
            ga_session_str = (row.get("GA Session") or "").strip()
            meeting_date_str = (row.get("Meeting Date") or "").strip()
            meeting_symbol = (row.get("Meeting Symbol") or "").strip()
            undl_id = (row.get("UNDL ID") or "").strip() or None
            undl_link = (row.get("UNDL Link") or "").strip() or None

            if not raw_name or not member_state:
                skipped += 1
                continue

            try:
                ga_session = int(ga_session_str)
            except (ValueError, TypeError):
                log.debug("Unparseable GA session %r — skipping.", ga_session_str)
                skipped += 1
                continue

            # Resolve country
            canonical = normalize_country_name(member_state)
            country_id = country_idx.get(canonical)
            if country_id is None:
                log.debug("Country not found: %r (normalised: %r)", member_state, canonical)

            # Resolve document
            document_id = doc_idx.get(meeting_symbol)

            # Resolve speaker (best-effort)
            display_name = _normalise_name(raw_name)
            speaker_id = _find_speaker(session, display_name, country_id)

            meeting_date = _parse_date(meeting_date_str)

            log.debug(
                "  session=%d  country=%r  speaker=%r  doc_id=%s",
                ga_session,
                canonical,
                display_name,
                document_id,
            )

            if not dry_run:
                # Mark document as general debate
                if document_id:
                    session.execute(
                        text(
                            "UPDATE documents SET is_general_debate = TRUE "
                            "WHERE id = :doc_id AND is_general_debate = FALSE"
                        ),
                        {"doc_id": document_id},
                    )

                # Upsert general_debate_entries
                existing = session.execute(
                    text(
                        "SELECT id FROM general_debate_entries "
                        "WHERE ga_session = :s AND speaker_name = :n "
                        "AND (country_id = :c OR (country_id IS NULL AND :c IS NULL))"
                    ),
                    {"s": ga_session, "n": display_name, "c": country_id},
                ).fetchone()

                if existing:
                    session.execute(
                        text(
                            "UPDATE general_debate_entries SET "
                            "document_id = :doc, speaker_id = :spk, "
                            "salutation = :sal, meeting_date = :md, "
                            "undl_id = :uid, undl_link = :ul "
                            "WHERE id = :id"
                        ),
                        {
                            "doc": document_id,
                            "spk": speaker_id,
                            "sal": salutation,
                            "md": meeting_date,
                            "uid": undl_id,
                            "ul": undl_link,
                            "id": existing[0],
                        },
                    )
                    updated += 1
                else:
                    session.execute(
                        text(
                            "INSERT INTO general_debate_entries "
                            "(document_id, country_id, speaker_id, speaker_name, "
                            " salutation, ga_session, meeting_date, undl_id, undl_link) "
                            "VALUES (:doc, :c, :spk, :n, :sal, :s, :md, :uid, :ul)"
                        ),
                        {
                            "doc": document_id,
                            "c": country_id,
                            "spk": speaker_id,
                            "n": display_name,
                            "sal": salutation,
                            "s": ga_session,
                            "md": meeting_date,
                            "uid": undl_id,
                            "ul": undl_link,
                        },
                    )
                    inserted += 1
            else:
                inserted += 1  # count as "would insert" for dry-run reporting

    return inserted, updated, skipped


def import_undl_general_debate(
    db_url: str | None = None,
    csv_path: Path | None = None,
    download: bool = False,
    dry_run: bool = False,
) -> None:
    engine = get_engine(db_url)
    create_schema(engine)

    with get_session(engine) as session:
        _ensure_schema(session)

    if csv_path is None:
        csv_path = _DATA_DIR / "GA_debate_speech_dataset_20260129.csv"

    _download(_CSV_URL, csv_path, force=download)

    with get_session(engine) as session:
        inserted, updated, skipped = _import_csv(session, csv_path, dry_run)

    action = "Would insert" if dry_run else "Inserted"
    log.info(
        "%s %d general debate entries, updated %d, skipped %d.",
        action,
        inserted,
        updated,
        skipped,
    )


def main() -> int:
    p = argparse.ArgumentParser(
        description="Import UN General Debate speeches metadata into the database.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument("--csv", default=None, help="Path to local CSV file")
    p.add_argument(
        "--download",
        action="store_true",
        help="Force re-download even if cached file exists",
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

    import_undl_general_debate(
        db_url=args.db,
        csv_path=Path(args.csv) if args.csv else None,
        download=args.download,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
