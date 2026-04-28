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
from datetime import date
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from scripts.fix_country_duplicates import fix_duplicates
from src.db.database import create_schema, get_engine, get_session, run_migrations
from src.extraction.country_aliases import normalize_country_name
from src.db.models import (
    Country,
    CountryVote,
    Document,
    DocumentItem,
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


_MAX_COUNTRY_NAME_LEN = 80  # longest real name is ~55 chars

# If the same (name, country) key appears in a document whose date is more
# than this many years after the speaker's first_seen_date, the deduplication
# is likely wrong (different person with the same name).
_SPEAKER_SAME_PERSON_MAX_YEARS: int = 15


def _get_or_create_country(session: Session, name: str) -> Country | None:
    name = normalize_country_name(name)
    if not name or name.lower() == "none":
        log.warning("Skipping blank/null country name")
        return None
    if len(name) > _MAX_COUNTRY_NAME_LEN:
        log.warning(
            "Skipping implausible country name (%d chars): %.60s…", len(name), name
        )
        return None
    obj = session.query(Country).filter_by(name=name).first()
    if obj is None:
        try:
            with session.begin_nested():
                obj = Country(name=name)
                session.add(obj)
                session.flush()
        except IntegrityError:
            # Another concurrent worker inserted the same country first.
            obj = session.query(Country).filter_by(name=name).first()
    return obj  # type: ignore[no-any-return]


def _get_or_create_speaker(
    session: Session,
    name: str,
    country: Country | None,
    organization: str | None,
    role: str | None,
    title: str | None,
    doc_date: date | None = None,
) -> Speaker:
    country_id = country.id if country else None
    obj = (
        session.query(Speaker)
        .filter_by(name=name, country_id=country_id, organization=organization)
        .first()
    )
    if obj is None:
        try:
            with session.begin_nested():
                obj = Speaker(
                    name=name,
                    country_id=country_id,
                    organization=organization,
                    role=role,
                    title=title,
                    first_seen_date=doc_date,
                )
                session.add(obj)
                session.flush()
        except IntegrityError:
            # Another concurrent worker inserted the same speaker first.
            obj = (
                session.query(Speaker)
                .filter_by(name=name, country_id=country_id, organization=organization)
                .first()
            )
    assert (
        obj is not None
    ), f"Speaker ({name!r}, country_id={country_id}) vanished after IntegrityError"

    # Keep first_seen_date as the earliest observed date, and warn when the
    # gap is large enough to suggest a different person with the same name.
    if doc_date is not None:
        if obj.first_seen_date is None or doc_date < obj.first_seen_date:
            obj.first_seen_date = doc_date
            session.flush()
        elif obj.first_seen_date is not None:
            gap_years = (doc_date - obj.first_seen_date).days / 365.25
            if gap_years > _SPEAKER_SAME_PERSON_MAX_YEARS:
                country_name = country.name if country else "no country"
                log.warning(
                    "Possible speaker identity collision: %s (%s) — "
                    "first seen %s, now %s (gap %.0f years)",
                    name,
                    country_name,
                    obj.first_seen_date,
                    doc_date,
                    gap_years,
                )

    return obj  # type: ignore[no-any-return]


def _get_or_create_resolution(
    session: Session,
    draft_symbol: str,
    body: str,
    session_num: int | None,
    title: str | None = None,
) -> Resolution:
    obj = session.query(Resolution).filter_by(draft_symbol=draft_symbol).first()
    if obj is None:
        obj = Resolution(
            draft_symbol=draft_symbol, body=body, session=session_num, title=title
        )
        session.add(obj)
        session.flush()
    elif title and not obj.title:
        obj.title = title
        session.flush()
    return obj  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Main importer
# ---------------------------------------------------------------------------


def _delete_document(db_session: Session, doc: Document) -> None:
    """Delete a document and all its dependent rows (preserving resolutions)."""
    vote_ids = [v.id for v in db_session.query(Vote.id).filter_by(document_id=doc.id)]
    if vote_ids:
        db_session.query(CountryVote).filter(CountryVote.vote_id.in_(vote_ids)).delete(
            synchronize_session=False
        )
    db_session.query(Vote).filter_by(document_id=doc.id).delete(
        synchronize_session=False
    )
    db_session.query(Speech).filter_by(document_id=doc.id).delete(
        synchronize_session=False
    )
    db_session.query(StageDirection).filter_by(document_id=doc.id).delete(
        synchronize_session=False
    )
    db_session.query(DocumentItem).filter_by(document_id=doc.id).delete(
        synchronize_session=False
    )
    db_session.delete(doc)
    db_session.flush()


def import_record(
    db_session: Session, record: MeetingRecord, recreate: bool = False
) -> None:
    """Import one ``MeetingRecord`` into the database."""
    with db_session.begin_nested():
        # Serialize concurrent workers that might import the same document
        # simultaneously.  pg_advisory_xact_lock is released automatically when
        # the surrounding transaction commits or rolls back.
        # Advisory locks are a PostgreSQL extension; skip on other backends
        # (SQLite is used in tests).
        if db_session.get_bind().dialect.name == "postgresql":
            db_session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:sym))"),
                {"sym": record.symbol},
            )

        # Document
        doc = db_session.query(Document).filter_by(symbol=record.symbol).first()
        if doc is not None:
            if not recreate:
                log.info("Document %s already in DB — skipping", record.symbol)
                return
            log.info("Document %s already in DB — deleting for recreate", record.symbol)
            _delete_document(db_session, doc)

        doc = Document(
            symbol=record.symbol,
            body=record.body,
            meeting_number=record.meeting_number,
            session=record.session,
            date=record.date,
            location=record.location,
            ocr_quality_score=record.ocr_quality_score,
            ocr_quality_label=record.ocr_quality_label,
            ods_used=record.ods_used,
        )
        db_session.add(doc)
        db_session.flush()

        # Iterate items in document order
        for item_data in record.items:
            db_item = DocumentItem(
                document_id=doc.id,
                position=item_data.position,
                item_type=item_data.item_type,
                title=item_data.title,
                agenda_number=item_data.agenda_number,
                sub_item=item_data.sub_item,
                continued=item_data.continued,
            )
            db_session.add(db_item)
            db_session.flush()

            # Stage directions
            for sd in item_data.stage_directions:
                obj = StageDirection(
                    document_id=doc.id,
                    item_id=db_item.id,
                    text=sd.text,
                    direction_type=sd.direction_type,
                    position_in_document=sd.position,
                    position_in_item=sd.position_in_item,
                )
                db_session.add(obj)

            # Speeches
            for speech in item_data.speeches:
                sp = speech.speaker
                country: Country | None = None
                if sp.country:
                    country = _get_or_create_country(db_session, sp.country)

                speaker = _get_or_create_speaker(
                    db_session,
                    name=sp.name,
                    country=country,
                    organization=sp.organization,
                    role=sp.role,
                    title=sp.title,
                    doc_date=record.date,
                )
                obj_speech = Speech(
                    document_id=doc.id,
                    item_id=db_item.id,
                    speaker_id=speaker.id,
                    language=sp.language,
                    on_behalf_of=sp.on_behalf_of,
                    text=speech.text,
                    position_in_document=speech.position,
                    position_in_item=speech.position_in_item,
                )
                db_session.add(obj_speech)

            # Resolutions and votes
            for res in item_data.resolutions:
                resolution = _get_or_create_resolution(
                    db_session, res.draft_symbol, record.body, record.session, res.title
                )
                if res.adopted_symbol and not resolution.adopted_symbol:
                    resolution.adopted_symbol = res.adopted_symbol
                    db_session.flush()

                vote = Vote(
                    document_id=doc.id,
                    item_id=db_item.id,
                    resolution_id=resolution.id,
                    vote_type=res.vote_type,
                    vote_scope="whole_resolution",
                    yes_count=res.yes_count,
                    no_count=res.no_count,
                    abstain_count=res.abstain_count,
                    position_in_item=res.position_in_item,
                )
                db_session.add(vote)
                db_session.flush()

                seen_country_ids: set[int] = set()
                skipped: list[str] = []
                for cv in res.country_votes:
                    country = _get_or_create_country(db_session, cv.country)
                    if country is None:
                        continue
                    if country.id in seen_country_ids:
                        skipped.append(cv.country)
                        continue
                    seen_country_ids.add(country.id)
                    obj_cv = CountryVote(
                        vote_id=vote.id,
                        country_id=country.id,
                        vote_position=cv.vote_position,
                    )
                    db_session.add(obj_cv)
                if skipped:
                    log.warning(
                        "%s: skipped %d duplicate country vote(s) for %s: %s",
                        record.symbol,
                        len(skipped),
                        res.draft_symbol,
                        ", ".join(skipped),
                    )

        db_session.flush()
    log.info("Imported %s", record.symbol)


def import_directory(
    json_dir: Path, db_url: str | None = None, recreate: bool = False
) -> None:
    """Import all JSON files in *json_dir* into the database."""
    json_files = sorted(json_dir.glob("meeting_*.json"))
    if not json_files:
        log.warning("No meeting_*.json files found in %s", json_dir)
        return

    engine = get_engine(db_url)
    if engine.dialect.name == "postgresql":
        run_migrations(db_url)
    else:
        create_schema(engine)

    ok = 0
    failed = 0
    for json_path in json_files:
        try:
            with json_path.open(encoding="utf-8") as fh:
                data = json.load(fh)
            record = MeetingRecord.model_validate(data)
            with get_session(engine) as session:
                import_record(session, record, recreate=recreate)
            ok += 1
        except Exception as exc:
            log.error("Failed to import %s: %s", json_path.name, exc)
            failed += 1

    log.info("Import complete: %d ok, %d failed", ok, failed)
    log.info("Running fix_country_duplicates …")
    fix_duplicates(engine=engine)


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
    p.add_argument(
        "--recreate",
        action="store_true",
        default=False,
        help="Delete and re-import documents that already exist in the database",
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
        import_directory(args.json_dir, db_url=args.db, recreate=args.recreate)
    except Exception as exc:
        log.error("Import aborted: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
