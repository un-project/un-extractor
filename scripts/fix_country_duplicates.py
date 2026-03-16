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

from src.db.database import get_engine, get_session
from src.db.models import Country, CountryVote, Speaker, Speech
from src.extraction.country_aliases import _ALIASES

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
    """Remove country rows with blank or sentinel names (e.g. 'None', '')."""
    junk = (
        session.query(Country)
        .filter(Country.name.in_(["", "None", "none", "NULL", "null"]))
        .all()
    )
    for row in junk:
        log.info("DELETE junk country row id=%d name=%r", row.id, row.name)
        if not dry_run:
            # Detach any speakers / country_votes that reference this row
            session.query(Speaker).filter_by(country_id=row.id).update(
                {"country_id": None}
            )
            session.query(CountryVote).filter_by(country_id=row.id).delete()
            session.delete(row)
            session.flush()


def fix_duplicates(db_url: str | None = None, dry_run: bool = False) -> None:
    engine = get_engine(db_url)

    countries_merged = 0
    countries_renamed = 0

    with get_session(engine) as session:
        _delete_junk_rows(session, dry_run)

        for alias_name, canonical_name in _ALIASES.items():
            alias_row = (
                session.query(Country)
                .filter(Country.name.ilike(alias_name))
                .first()
            )
            if alias_row is None:
                continue

            canonical_row = (
                session.query(Country).filter_by(name=canonical_name).first()
            )

            if canonical_row is not None and canonical_row.id == alias_row.id:
                continue

            if canonical_row is not None:
                # Both exist — merge alias into canonical.
                log.info(
                    "MERGE country %r (id=%d) → %r (id=%d)",
                    alias_row.name,
                    alias_row.id,
                    canonical_row.name,
                    canonical_row.id,
                )
                _merge_speakers(session, alias_row.id, canonical_row.id, dry_run)
                _merge_country_votes(session, alias_row.id, canonical_row.id, dry_run)
                if not dry_run:
                    session.delete(alias_row)
                    session.flush()
                countries_merged += 1
            else:
                # Only alias exists — rename in-place.
                log.info("RENAME %r → %r", alias_row.name, canonical_name)
                if not dry_run:
                    alias_row.name = canonical_name
                    session.flush()
                countries_renamed += 1

    action = "Would merge" if dry_run else "Merged"
    log.info(
        "%s %d country rows, renamed %d rows.",
        action,
        countries_merged,
        countries_renamed,
    )


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
