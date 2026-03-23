#!/usr/bin/env python3
"""DB migration: merge duplicate country rows caused by OCR typos / short names.

For each alias → canonical mapping in ``country_aliases``:

1. If both an alias country row and a canonical country row exist:
   a. For each speaker linked to the alias country:
      - If a speaker with the same name already exists under the canonical
        country, reassign that alias speaker's speeches to the canonical
        speaker and delete the alias speaker.
      - Otherwise update speaker.country_id to the canonical country.
   b. For each country_vote linked to the alias country:
      - If a country_vote for the same (vote_id, canonical_country_id) already
        exists, delete the duplicate.
      - Otherwise update country_vote.country_id to the canonical country.
   c. Delete the alias country row.

2. If only the alias country row exists (no canonical yet):
   - Rename the alias row in-place to the canonical name.

3. If only the canonical row exists (or neither): nothing to do.

Usage
-----
    python scripts/fix_country_duplicates.py
    python scripts/fix_country_duplicates.py --db postgresql://user:pass@host/db
    python scripts/fix_country_duplicates.py --dry-run
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Allow running from repo root without installing the package
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import func

from src.db.database import get_engine, get_session
from src.db.models import Country, CountryVote, Speaker, Speech
from src.extraction.country_aliases import _ALIASES, normalize_country_name

log = logging.getLogger(__name__)


def _merge_speakers(session, alias_country_id: int, canonical_country_id: int, dry_run: bool) -> int:
    """Reassign speakers from alias country to canonical country.

    When a speaker with (name, canonical_country_id) already exists, their
    speeches are redirected to the canonical speaker and the alias speaker is
    deleted.  Returns the number of speakers processed.
    """
    alias_speakers = (
        session.query(Speaker).filter_by(country_id=alias_country_id).all()
    )
    for alias_spk in alias_speakers:
        canonical_spk = (
            session.query(Speaker)
            .filter_by(name=alias_spk.name, country_id=canonical_country_id)
            .first()
        )
        if canonical_spk is not None:
            # Duplicate speaker exists — redirect speeches then delete alias.
            speech_count = (
                session.query(Speech).filter_by(speaker_id=alias_spk.id).count()
            )
            log.info(
                "  MERGE speaker %r (id=%d) → id=%d  (%d speeches)",
                alias_spk.name,
                alias_spk.id,
                canonical_spk.id,
                speech_count,
            )
            if not dry_run:
                session.query(Speech).filter_by(speaker_id=alias_spk.id).update(
                    {"speaker_id": canonical_spk.id}
                )
                session.delete(alias_spk)
                session.flush()
        else:
            log.info(
                "  MOVE speaker %r (id=%d) → country_id=%d",
                alias_spk.name,
                alias_spk.id,
                canonical_country_id,
            )
            if not dry_run:
                alias_spk.country_id = canonical_country_id
                session.flush()

    return len(alias_speakers)


def _merge_country_votes(session, alias_country_id: int, canonical_country_id: int, dry_run: bool) -> int:
    """Reassign country_votes from alias country to canonical country.

    When a (vote_id, canonical_country_id) row already exists the duplicate is
    deleted.  Returns the number of country_votes processed.
    """
    alias_votes = (
        session.query(CountryVote).filter_by(country_id=alias_country_id).all()
    )
    for cv in alias_votes:
        duplicate = (
            session.query(CountryVote)
            .filter_by(vote_id=cv.vote_id, country_id=canonical_country_id)
            .first()
        )
        if duplicate is not None:
            log.info(
                "  DROP duplicate country_vote id=%d (vote_id=%d, already has canonical)",
                cv.id,
                cv.vote_id,
            )
            if not dry_run:
                session.delete(cv)
                session.flush()
        else:
            if not dry_run:
                cv.country_id = canonical_country_id
                session.flush()

    return len(alias_votes)


def _delete_junk_rows(session, dry_run: bool) -> None:
    """Remove country rows with blank, sentinel, or hopelessly garbled names."""
    junk = (
        session.query(Country)
        .filter(
            Country.name.in_(
                [
                    "",
                    "None",
                    "none",
                    "NULL",
                    "null",
                    "&",
                    "Aviva",
                    "Coast",
                    "Pem",
                    # Concatenated multi-country OCR artifacts
                    "United States of America. I'pper Volta",
                    "United States of America Austria",
                    "Surinam United Kingdom of Gre United States of America",
                    "United Republic of Tanzania and United States of America",
                    "United States of America and Venezuela (Bolivarian Republic of)",
                    "United States of America and Uruguay",
                    # Speech fragments stored as country names
                    "None United States of America",
                ]
            )
        )
        .all()
    )
    # Also delete rows whose name is longer than 100 chars — these are speech
    # fragments or other garbage that got stored as country names.
    junk += (
        session.query(Country)
        .filter(func.length(Country.name) > 100)
        .all()
    )

    seen_ids: set[int] = set()
    for row in junk:
        if row.id in seen_ids:
            continue
        seen_ids.add(row.id)
        log.info("DELETE junk country row id=%d name=%r", row.id, row.name[:80])
        if not dry_run:
            # Detach any speakers / country_votes that reference this row
            session.query(Speaker).filter_by(country_id=row.id).update(
                {"country_id": None}
            )
            session.query(CountryVote).filter_by(country_id=row.id).delete()
            session.delete(row)
            session.flush()


def _normalize_existing_rows(session, dry_run: bool) -> tuple[int, int]:
    """Apply ``normalize_country_name`` to every country row.

    For each row whose name changes after normalization:
    - If a row with the canonical name already exists → merge.
    - Otherwise → rename in-place.

    Each row is wrapped in a savepoint so a single failure doesn't roll back
    the entire session.

    Returns (renamed, merged).
    """
    renamed = 0
    merged = 0

    # Load all rows up-front; iterate a stable snapshot.
    all_rows = session.query(Country).order_by(Country.id).all()
    for row in all_rows:
        canonical_name = normalize_country_name(row.name)
        if canonical_name == row.name:
            continue

        # Re-query to handle rows already renamed in this loop.
        canonical_row = session.query(Country).filter_by(name=canonical_name).first()

        try:
            sp = session.begin_nested()
            if canonical_row is None or canonical_row.id == row.id:
                log.info("RENAME %r → %r", row.name, canonical_name)
                if not dry_run:
                    row.name = canonical_name
                    session.flush()
                renamed += 1
            else:
                log.info(
                    "MERGE country %r (id=%d) → %r (id=%d)",
                    row.name,
                    row.id,
                    canonical_name,
                    canonical_row.id,
                )
                _merge_speakers(session, row.id, canonical_row.id, dry_run)
                _merge_country_votes(session, row.id, canonical_row.id, dry_run)
                if not dry_run:
                    # Transfer iso3 to canonical row if alias owns it
                    if row.iso3 and not canonical_row.iso3:
                        canonical_row.iso3 = row.iso3
                        row.iso3 = None
                        session.flush()
                    session.delete(row)
                    session.flush()
                merged += 1
            sp.commit()
        except Exception as exc:
            sp.rollback()
            log.warning(
                "SKIP %r → %r: %s", row.name, canonical_name, exc
            )

    return renamed, merged


def fix_duplicates(db_url: str | None = None, dry_run: bool = False) -> None:
    engine = get_engine(db_url)

    with get_session(engine) as session:
        _delete_junk_rows(session, dry_run)
        renamed, merged = _normalize_existing_rows(session, dry_run)

    action = "Would merge" if dry_run else "Merged"
    log.info("%s %d country rows, renamed %d rows.", action, merged, renamed)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Merge duplicate country rows in the database.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would change without modifying the database",
    )
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    fix_duplicates(db_url=args.db, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
