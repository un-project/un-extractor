#!/usr/bin/env python3
"""CLI: import extracted JSON meeting records into PostgreSQL.

Usage
-----
    python import_json_to_db.py output/
    python import_json_to_db.py output/ --db postgresql://user:pass@host/db
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from sqlalchemy.orm import Session

from src.db.database import create_schema, get_engine, get_session
from src.db.models import (
    Country,
    CountryVote,
    Document,
    Resolution,
    Speaker,
    Speech,
    StageDirection,
    Vote,
)
from src.models import MeetingRecord

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lookup / upsert helpers
# ---------------------------------------------------------------------------


def _get_or_create_country(session: Session, name: str) -> Country:
    obj = session.query(Country).filter_by(name=name).first()
    if obj is None:
        obj = Country(name=name)
        session.add(obj)
        session.flush()
    return obj  # type: ignore[return-value]


def _get_or_create_speaker(
    session: Session,
    name: str,
    country: Country | None,
    role: str | None,
    title: str | None,
) -> Speaker:
    country_id = country.id if country else None
    obj = session.query(Speaker).filter_by(name=name, country_id=country_id).first()
    if obj is None:
        obj = Speaker(name=name, country_id=country_id, role=role, title=title)
        session.add(obj)
        session.flush()
    return obj  # type: ignore[return-value]


def _get_or_create_resolution(
    session: Session, draft_symbol: str, body: str, session_num: int | None
) -> Resolution:
    obj = session.query(Resolution).filter_by(draft_symbol=draft_symbol).first()
    if obj is None:
        obj = Resolution(draft_symbol=draft_symbol, body=body, session=session_num)
        session.add(obj)
        session.flush()
    return obj  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Main importer
# ---------------------------------------------------------------------------


def import_record(db_session: Session, record: MeetingRecord) -> None:
    """Import one ``MeetingRecord`` into the database."""
    # Document
    doc = db_session.query(Document).filter_by(symbol=record.symbol).first()
    if doc is None:
        doc = Document(
            symbol=record.symbol,
            body=record.body,
            meeting_number=record.meeting_number,
            session=record.session,
            date=record.date,
            location=record.location,
        )
        db_session.add(doc)
        db_session.flush()
    else:
        log.info("Document %s already in DB — skipping", record.symbol)
        return

    # Stage directions
    for sd in record.stage_directions:
        obj = StageDirection(
            document_id=doc.id,
            text=sd.text,
            direction_type=sd.direction_type,
            position_in_document=sd.position,
        )
        db_session.add(obj)

    # Speeches
    for speech in record.speeches:
        sp = speech.speaker
        country: Country | None = None
        if sp.country:
            country = _get_or_create_country(db_session, sp.country)

        speaker = _get_or_create_speaker(
            db_session,
            name=sp.name,
            country=country,
            role=sp.role,
            title=sp.title,
        )
        obj_speech = Speech(
            document_id=doc.id,
            speaker_id=speaker.id,
            language=sp.language,
            on_behalf_of=sp.on_behalf_of,
            text=speech.text,
            position_in_document=speech.position,
        )
        db_session.add(obj_speech)

    # Resolutions and votes
    for res in record.resolutions:
        resolution = _get_or_create_resolution(
            db_session, res.draft_symbol, record.body, record.session
        )
        if res.adopted_symbol and not resolution.adopted_symbol:
            resolution.adopted_symbol = res.adopted_symbol
            db_session.flush()

        vote = Vote(
            document_id=doc.id,
            resolution_id=resolution.id,
            vote_type=res.vote_type,
            vote_scope="whole_resolution",
            yes_count=res.yes_count,
            no_count=res.no_count,
            abstain_count=res.abstain_count,
        )
        db_session.add(vote)
        db_session.flush()

        for cv in res.country_votes:
            country = _get_or_create_country(db_session, cv.country)
            obj_cv = CountryVote(
                vote_id=vote.id,
                country_id=country.id,
                vote_position=cv.vote_position,
            )
            db_session.add(obj_cv)

    db_session.flush()
    log.info("Imported %s", record.symbol)


def import_directory(json_dir: Path, db_url: str | None = None) -> None:
    """Import all JSON files in *json_dir* into the database."""
    json_files = sorted(json_dir.glob("meeting_*.json"))
    if not json_files:
        log.warning("No meeting_*.json files found in %s", json_dir)
        return

    engine = get_engine(db_url)
    create_schema(engine)

    ok = 0
    failed = 0
    with get_session(engine) as session:
        for json_path in json_files:
            try:
                with json_path.open(encoding="utf-8") as fh:
                    data = json.load(fh)
                record = MeetingRecord.model_validate(data)
                import_record(session, record)
                ok += 1
            except Exception as exc:
                log.error("Failed to import %s: %s", json_path.name, exc)
                failed += 1

    log.info("Import complete: %d ok, %d failed", ok, failed)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Import extracted JSON meeting records into PostgreSQL.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "json_dir", type=Path, help="Directory containing meeting_*.json files"
    )
    p.add_argument(
        "--db", default=None, help="Database URL (overrides DATABASE_URL env var)"
    )
    p.add_argument("--verbose", action="store_true", default=False)
    return p


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    if not args.json_dir.exists():
        print(f"Error: {args.json_dir} does not exist", file=sys.stderr)
        return 1

    try:
        import_directory(args.json_dir, db_url=args.db)
    except Exception as exc:
        log.error("Import aborted: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
