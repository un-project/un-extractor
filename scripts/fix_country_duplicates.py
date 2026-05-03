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
    python scripts/fix_country_duplicates.py --report
"""

from __future__ import annotations

import argparse
import difflib
import logging
import re
import sys
from pathlib import Path

# Allow running from repo root without installing the package
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pycountry  # noqa: E402
from sqlalchemy import Engine, func, select, text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import get_engine, get_session  # noqa: E402
from src.db.models import Country, CountryVote, Speaker, Speech  # noqa: E402
from src.extraction.country_aliases import (  # noqa: E402
    _CANONICAL_NAMES,
    normalize_country_name,
)

# Preferred display names — override pycountry's comma-inverted format to match
# the natural UN-style names used throughout the codebase and the old database.
_PREFERRED_NAMES: dict[str, str] = {
    "BOL": "Plurinational State of Bolivia",
    "COD": "Democratic Republic of the Congo",
    "FSM": "Micronesia (Federated States of)",
    "GBR": "United Kingdom of Great Britain and Northern Ireland",
    "IRN": "Islamic Republic of Iran",
    "KOR": "Republic of Korea",
    "MDA": "Moldova",
    "PRK": "Democratic People's Republic of Korea",
    "PSE": "State of Palestine",
    "TZA": "United Republic of Tanzania",
    "USA": "United States of America",
    "VAT": "Holy See",
    "VEN": "Bolivarian Republic of Venezuela",
}

# Canonical names for historical/defunct countries not in pycountry current list.
_HISTORICAL_CANONICAL: dict[str, str] = {
    "YUG": "Yugoslavia",
    "SUN": "Union of Soviet Socialist Republics",
    "CSK": "Czechoslovakia",
    "DDR": "German Democratic Republic",
    "ZAR": "Zaire",
    "ANT": "Netherlands Antilles",
    "SCG": "Serbia and Montenegro",
    "VDR": "Democratic Republic of Viet-Nam",
    "YMD": "Democratic Yemen",
    "HVO": "Upper Volta",
    "DHY": "Dahomey",
    "RHO": "Southern Rhodesia",
    "BUR": "Burma",
    "BYS": "Byelorussian Soviet Socialist Republic",
    "GER": "Germany, Federal Republic of",
    "EAT": "Tanganyika",
    "EAZ": "Zanzibar",
    "UAR": "United Arab Republic",
}


def _canonical_name_from_iso3(iso3: str) -> str | None:
    """Return the canonical country name for an ISO 3166 alpha-3 code.

    Checks _PREFERRED_NAMES first so the natural UN-style format wins over
    pycountry's comma-inverted form (e.g. "United Republic of Tanzania" not
    "Tanzania, United Republic of").
    """
    if iso3 in _PREFERRED_NAMES:
        return _PREFERRED_NAMES[iso3]
    if iso3 in _HISTORICAL_CANONICAL:
        return _HISTORICAL_CANONICAL[iso3]
    c = pycountry.countries.get(alpha_3=iso3)
    if c:
        return c.name
    hc = pycountry.historic_countries.get(alpha_3=iso3)
    if hc:
        return hc.name
    return None


# ---------------------------------------------------------------------------
# Pycountry name → iso3 lookup (used for fuzzy matching of no-iso3 rows)
# ---------------------------------------------------------------------------

def _build_pycountry_lookup() -> dict[str, str]:
    """Return a mapping from lowercase name variant → iso3 code."""
    lookup: dict[str, str] = {}
    for c in pycountry.countries:
        a3 = c.alpha_3
        lookup[c.name.lower()] = a3
        if hasattr(c, "common_name"):
            lookup[c.common_name.lower()] = a3
        if hasattr(c, "official_name"):
            lookup[c.official_name.lower()] = a3
    for c in pycountry.historic_countries:
        a3 = c.alpha_3
        lookup[c.name.lower()] = a3
        if hasattr(c, "common_name"):
            lookup[c.common_name.lower()] = a3
    # Add preferred names and historical canonical names so fuzzy matching
    # produces the correct iso3 for variants like "United Republic of Tanzania".
    for iso3, name in _PREFERRED_NAMES.items():
        lookup[name.lower()] = iso3
    for iso3, name in _HISTORICAL_CANONICAL.items():
        lookup[name.lower()] = iso3
    return lookup


_PYCOUNTRY_NAMES: dict[str, str] = _build_pycountry_lookup()
_PYCOUNTRY_NAMES_LIST: list[str] = list(_PYCOUNTRY_NAMES.keys())


def _fuzzy_iso3(name: str, cutoff: float = 0.82) -> str | None:
    """Return iso3 for the best fuzzy pycountry match, or None if no good match."""
    if len(name.strip()) < 4:
        return None
    matches = difflib.get_close_matches(name.lower(), _PYCOUNTRY_NAMES_LIST, n=1, cutoff=cutoff)
    return _PYCOUNTRY_NAMES[matches[0]] if matches else None

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Junk-detection patterns (applied to country rows without iso3 codes)
# ---------------------------------------------------------------------------

# Pattern 1: starts with a non-letter (catches "(C)", "!'K;Ngol", "21", "*Subsequently")
_JUNK_STARTS_NON_LETTER = re.compile(r"^[^A-Za-zÀ-ÖØ-öø-ÿ]")

# Pattern 2: procedural/assembly text fragments
_JUNK_PROCEDURAL = re.compile(
    r"\b(I shall|put to the vote|preambular|recorded vote has been|"
    r"operative paragraph|draft resolution|budget implications|"
    r"I would like to inform|I should like to|programme budget|"
    r"is postponed|noted that action|agenda item \d|"
    r"recommended by|entitled|shall first|take it that)\b",
    re.IGNORECASE,
)

# Pattern 3: concatenated countries — tilde/semicolon followed by uppercase
_JUNK_CONCAT_TILDE = re.compile(r"[~;]\s*[A-Z]")

# Pattern 4: concatenated countries — period space + Title-case word
_JUNK_CONCAT_DOT = re.compile(r"\.\s+[A-Z][a-z]")


def _merge_speakers(
    session: Session, alias_country_id: int, canonical_country_id: int, dry_run: bool
) -> int:
    """Reassign speakers from alias country to canonical country.

    When a speaker with (name, canonical_country_id) already exists, their
    speeches are redirected to the canonical speaker and the alias speaker is
    deleted.  Returns the number of speakers processed.
    """
    alias_speakers = session.query(Speaker).filter_by(country_id=alias_country_id).all()
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


def _merge_country_votes(
    session: Session, alias_country_id: int, canonical_country_id: int, dry_run: bool
) -> int:
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
                "  DROP duplicate country_vote id=%d (vote_id=%d, canonical exists)",
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


def _merge_additional_fks(
    session: Session, alias_country_id: int, canonical_country_id: int, dry_run: bool
) -> None:
    """Reassign country FK references in tables not covered by the ORM models.

    Handles: sc_representatives, permanent_representatives, general_debate_entries,
    resolution_sponsors, country_network_stats, country_alignment_series.
    For tables with unique constraints, duplicate rows are deleted before the
    UPDATE so no constraint violation occurs.
    """
    if dry_run:
        return

    a, c = alias_country_id, canonical_country_id

    # Simple reassigns (no unique constraint on country_id alone)
    session.execute(
        text("UPDATE sc_representatives SET country_id = :c WHERE country_id = :a"),
        {"c": c, "a": a},
    )
    session.execute(
        text("UPDATE permanent_representatives SET country_id = :c WHERE country_id = :a"),
        {"c": c, "a": a},
    )
    session.execute(
        text("UPDATE resolution_sponsors SET country_id = :c WHERE country_id = :a"),
        {"c": c, "a": a},
    )

    # veto_countries — unique on (veto_id, country_id)
    session.execute(
        text("""
            DELETE FROM veto_countries
            WHERE country_id = :a
              AND veto_id IN (SELECT veto_id FROM veto_countries WHERE country_id = :c)
        """),
        {"a": a, "c": c},
    )
    session.execute(
        text("UPDATE veto_countries SET country_id = :c WHERE country_id = :a"),
        {"c": c, "a": a},
    )

    # country_ideal_points — unique on (country_id, year, source)
    session.execute(
        text("""
            DELETE FROM country_ideal_points alias
            USING country_ideal_points canon
            WHERE alias.country_id = :a
              AND canon.country_id = :c
              AND alias.year = canon.year
              AND alias.source = canon.source
        """),
        {"a": a, "c": c},
    )
    session.execute(
        text("UPDATE country_ideal_points SET country_id = :c WHERE country_id = :a"),
        {"c": c, "a": a},
    )

    # voting_blocs — unique on (country_id, year) if such constraint exists; safe UPDATE
    session.execute(
        text("""
            DELETE FROM voting_blocs alias
            USING voting_blocs canon
            WHERE alias.country_id = :a
              AND canon.country_id = :c
              AND alias.year = canon.year
        """),
        {"a": a, "c": c},
    )
    session.execute(
        text("UPDATE voting_blocs SET country_id = :c WHERE country_id = :a"),
        {"c": c, "a": a},
    )

    # general_debate_entries — unique on (ga_session, speaker_name, country_id)
    session.execute(
        text("""
            DELETE FROM general_debate_entries alias
            USING general_debate_entries canon
            WHERE alias.country_id = :a
              AND canon.country_id = :c
              AND alias.ga_session  = canon.ga_session
              AND alias.speaker_name = canon.speaker_name
        """),
        {"a": a, "c": c},
    )
    session.execute(
        text("UPDATE general_debate_entries SET country_id = :c WHERE country_id = :a"),
        {"c": c, "a": a},
    )

    # country_network_stats — unique on (country_id, year)
    session.execute(
        text("""
            DELETE FROM country_network_stats
            WHERE country_id = :a
              AND year IN (SELECT year FROM country_network_stats WHERE country_id = :c)
        """),
        {"a": a, "c": c},
    )
    session.execute(
        text("UPDATE country_network_stats SET country_id = :c WHERE country_id = :a"),
        {"c": c, "a": a},
    )

    # country_alignment_series — CHECK (country_id_a < country_id_b),
    # UNIQUE (country_id_a, country_id_b, year).
    # When the canonical id is lower than the partner, the a/b columns must be
    # swapped to satisfy the check constraint.

    # Delete rows where one partner is alias and the other is canonical
    # (they would become self-references after the merge).
    session.execute(
        text("""
            DELETE FROM country_alignment_series
            WHERE (country_id_a = :a AND country_id_b = :c)
               OR (country_id_a = :c AND country_id_b = :a)
        """),
        {"a": a, "c": c},
    )
    # Delete canonical duplicates that would conflict after migrating alias rows.
    # Case: alias in a, canonical fits in a (no swap, c < partner_b)
    session.execute(
        text("""
            DELETE FROM country_alignment_series ex
            USING country_alignment_series al
            WHERE al.country_id_a = :a AND :c < al.country_id_b
              AND ex.country_id_a = :c AND ex.country_id_b = al.country_id_b
              AND ex.year = al.year
        """),
        {"a": a, "c": c},
    )
    # Case: alias in a, swap needed (c > partner_b → new row is (partner_b, c))
    session.execute(
        text("""
            DELETE FROM country_alignment_series ex
            USING country_alignment_series al
            WHERE al.country_id_a = :a AND :c > al.country_id_b
              AND ex.country_id_a = al.country_id_b AND ex.country_id_b = :c
              AND ex.year = al.year
        """),
        {"a": a, "c": c},
    )
    # Case: alias in b, no swap needed (c > partner_a → new row is (partner_a, c))
    session.execute(
        text("""
            DELETE FROM country_alignment_series ex
            USING country_alignment_series al
            WHERE al.country_id_b = :a AND :c > al.country_id_a
              AND ex.country_id_a = al.country_id_a AND ex.country_id_b = :c
              AND ex.year = al.year
        """),
        {"a": a, "c": c},
    )
    # Case: alias in b, swap needed (c < partner_a → new row is (c, partner_a))
    session.execute(
        text("""
            DELETE FROM country_alignment_series ex
            USING country_alignment_series al
            WHERE al.country_id_b = :a AND :c < al.country_id_a
              AND ex.country_id_a = :c AND ex.country_id_b = al.country_id_a
              AND ex.year = al.year
        """),
        {"a": a, "c": c},
    )
    # Update alias-in-a rows, swapping columns when canonical > partner_b.
    session.execute(
        text("UPDATE country_alignment_series SET country_id_a = :c WHERE country_id_a = :a AND :c < country_id_b"),
        {"c": c, "a": a},
    )
    session.execute(
        text("UPDATE country_alignment_series SET country_id_a = country_id_b, country_id_b = :c WHERE country_id_a = :a AND :c > country_id_b"),
        {"c": c, "a": a},
    )
    # Update alias-in-b rows, swapping columns when canonical < partner_a.
    session.execute(
        text("UPDATE country_alignment_series SET country_id_b = :c WHERE country_id_b = :a AND :c > country_id_a"),
        {"c": c, "a": a},
    )
    session.execute(
        text("UPDATE country_alignment_series SET country_id_b = country_id_a, country_id_a = :c WHERE country_id_b = :a AND :c < country_id_a"),
        {"c": c, "a": a},
    )

    session.flush()


def _delete_junk_rows(session: Session, dry_run: bool) -> None:
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
                    "Uruguay and Venezuela (Bolivarian Republic of)",
                    "Leb Paraguay;Uruguay",
                    "Lesotho Netherlands",
                    "Luxembourg 9 Netherlands",
                    "Unio Uruguay",
                    "Uruguay Aoainst: Angola",
                    "Uruguay f Van ua tu",
                    "Syrian Volunteers in the Netherlands",
                    # Speech fragments stored as country names
                    "None United States of America",
                ]
            )
        )
        .all()
    )
    # Also delete rows whose name is longer than 100 chars — these are speech
    # fragments or other garbage that got stored as country names.
    junk += session.query(Country).filter(func.length(Country.name) > 100).all()

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

    # Pattern-based detection
    pattern_junk = (
        session.query(Country)
        .filter(Country.iso3.is_(None))  # never delete a row that has a known iso3
        .all()
    )
    for row in pattern_junk:
        if row.id in seen_ids:
            continue
        name = row.name or ""
        if (
            len(name.strip()) < 3
            or _JUNK_STARTS_NON_LETTER.match(name)
            or _JUNK_PROCEDURAL.search(name)
            or _JUNK_CONCAT_TILDE.search(name)
            or _JUNK_CONCAT_DOT.search(name)
        ):
            seen_ids.add(row.id)
            log.info("DELETE junk country row id=%d name=%r", row.id, name[:80])
            if not dry_run:
                session.query(Speaker).filter_by(country_id=row.id).update(
                    {"country_id": None}
                )
                session.query(CountryVote).filter_by(country_id=row.id).delete()
                session.delete(row)
                session.flush()


def _normalize_existing_rows(session: Session, dry_run: bool) -> tuple[int, int]:
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
        # Fallback: if the alias table doesn't know this name but the row has
        # an iso3 code, derive the canonical name from pycountry.
        if canonical_name == row.name and row.iso3:
            iso3_name = _canonical_name_from_iso3(row.iso3)
            if iso3_name and iso3_name != row.name:
                canonical_name = iso3_name
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
                _merge_additional_fks(session, row.id, canonical_row.id, dry_run)
                if not dry_run:
                    if row.iso3:
                        # Clear the alias iso3 in its own flush FIRST.
                        # PostgreSQL checks the unique constraint after each
                        # statement, so both UPDATE statements cannot be
                        # batched in a single executemany: clearing the alias
                        # iso3 first ensures no two rows hold the same iso3
                        # at any point during the transaction.
                        alias_iso3 = row.iso3
                        row.iso3 = None
                        session.flush()
                        # Now transfer to canonical only if it has no iso3.
                        session.refresh(canonical_row)
                        if not canonical_row.iso3:
                            canonical_row.iso3 = alias_iso3
                            session.flush()
                    session.delete(row)
                    session.flush()
                merged += 1
            sp.commit()
        except Exception as exc:
            sp.rollback()
            log.warning("SKIP %r → %r: %s", row.name, canonical_name, exc)

    return renamed, merged


def _fuzzy_merge_no_iso3(session: Session, dry_run: bool) -> tuple[int, int]:
    """Fuzzy-match no-iso3 country rows against pycountry and merge matches.

    For each no-iso3 row whose name closely matches a known country (score
    >= 0.82):
    - If the canonical DB row (matching iso3) exists → merge.
    - If not → rename in-place and set iso3.

    Returns (renamed, merged).
    """
    renamed = 0
    merged = 0

    # Snapshot: canonical rows indexed by iso3
    canonical_by_iso3: dict[str, Country] = {
        c.iso3: c
        for c in session.query(Country).filter(Country.iso3.isnot(None)).all()
    }

    no_iso3_rows = (
        session.query(Country)
        .filter(Country.iso3.is_(None))
        .order_by(Country.id)
        .all()
    )

    for row in no_iso3_rows:
        name = (row.name or "").strip()
        if len(name) < 4:
            continue  # too short — will be handled by _delete_junk_rows

        iso3 = _fuzzy_iso3(name)
        if not iso3:
            continue

        preferred_name = _canonical_name_from_iso3(iso3)
        if not preferred_name:
            continue

        try:
            sp = session.begin_nested()
            canonical_row = canonical_by_iso3.get(iso3)
            if canonical_row is not None and canonical_row.id != row.id:
                log.info(
                    "FUZZY-MERGE %r (id=%d) → %r (id=%d)",
                    row.name, row.id, canonical_row.name, canonical_row.id,
                )
                _merge_speakers(session, row.id, canonical_row.id, dry_run)
                _merge_country_votes(session, row.id, canonical_row.id, dry_run)
                _merge_additional_fks(session, row.id, canonical_row.id, dry_run)
                if not dry_run:
                    session.delete(row)
                    session.flush()
                merged += 1
            elif canonical_row is None:
                log.info(
                    "FUZZY-RENAME %r → %r (iso3=%s)",
                    row.name, preferred_name, iso3,
                )
                if not dry_run:
                    row.name = preferred_name
                    row.iso3 = iso3
                    session.flush()
                    canonical_by_iso3[iso3] = row
                renamed += 1
            sp.commit()
        except Exception as exc:
            sp.rollback()
            log.warning("SKIP fuzzy %r: %s", name, exc)

    return renamed, merged


def _delete_remaining_no_iso3(session: Session, dry_run: bool) -> int:
    """Delete all remaining no-iso3 country rows (OCR garbage not matching any country).

    country_votes referencing them are deleted; speakers have their country_id
    set to NULL (preserving the speech text record).

    Returns the number of rows deleted.
    """
    rows = (
        session.query(Country)
        .filter(Country.iso3.is_(None))
        .order_by(Country.id)
        .all()
    )
    count = 0
    for row in rows:
        log.info(
            "DELETE garbage country id=%d name=%r", row.id, (row.name or "")[:80]
        )
        if not dry_run:
            session.execute(
                text("UPDATE speakers SET country_id = NULL WHERE country_id = :a"),
                {"a": row.id},
            )
            session.execute(
                text("DELETE FROM country_votes WHERE country_id = :a"),
                {"a": row.id},
            )
            session.execute(
                text("DELETE FROM resolution_sponsors WHERE country_id = :a"),
                {"a": row.id},
            )
            session.execute(
                text("DELETE FROM country_network_stats WHERE country_id = :a"),
                {"a": row.id},
            )
            session.execute(
                text("DELETE FROM country_ideal_points WHERE country_id = :a"),
                {"a": row.id},
            )
            session.execute(
                text("DELETE FROM voting_blocs WHERE country_id = :a"),
                {"a": row.id},
            )
            session.execute(
                text("DELETE FROM veto_countries WHERE country_id = :a"),
                {"a": row.id},
            )
            session.execute(
                text(
                    "DELETE FROM country_alignment_series "
                    "WHERE country_id_a = :a OR country_id_b = :a"
                ),
                {"a": row.id},
            )
            session.execute(
                text("DELETE FROM general_debate_entries WHERE country_id = :a"),
                {"a": row.id},
            )
            session.execute(
                text("DELETE FROM permanent_representatives WHERE country_id = :a"),
                {"a": row.id},
            )
            session.execute(
                text("DELETE FROM sc_representatives WHERE country_id = :a"),
                {"a": row.id},
            )
            session.delete(row)
            session.flush()
        count += 1
    return count


def _print_report(db_url: str | None = None) -> None:
    """Print a data-quality summary for the countries table.

    Sections
    --------
    1. Countries with no iso3, ordered by speech+vote usage (most referenced
       first).  These are the highest-priority rows to investigate.

    2. Subset of (1) whose name is not a recognised canonical country name —
       i.e. it does not appear as a value in the alias table.  These are
       candidates for new entries in ``country_aliases.py``.

    3. Official UN member states (``un_member_since IS NOT NULL``) that are
       still missing an iso3 code.  These were matched by name during
       ``import_undl_member_states.py`` but no iso3 could be assigned.

    4. Heuristically suspicious names — no iso3 rows that match one or more
       garbled-name heuristics (short, starts with non-letter, contains a
       digit, or very long).  Useful for spotting new OCR artifacts after a
       pipeline rerun without scanning the full no-iso3 list.
    """
    engine = get_engine(db_url)

    with get_session(engine) as session:
        # ------------------------------------------------------------------
        # Build usage-count subqueries
        # ------------------------------------------------------------------
        speech_sq = (
            select(Speaker.country_id, func.count(Speech.id).label("n"))
            .join(Speech, Speech.speaker_id == Speaker.id)
            .group_by(Speaker.country_id)
            .subquery()
        )
        vote_sq = (
            select(CountryVote.country_id, func.count(CountryVote.id).label("n"))
            .group_by(CountryVote.country_id)
            .subquery()
        )
        total = (
            func.coalesce(speech_sq.c.n, 0) + func.coalesce(vote_sq.c.n, 0)
        )

        no_iso3 = (
            session.query(
                Country.name,
                func.coalesce(speech_sq.c.n, 0).label("speeches"),
                func.coalesce(vote_sq.c.n, 0).label("votes"),
            )
            .outerjoin(speech_sq, speech_sq.c.country_id == Country.id)
            .outerjoin(vote_sq, vote_sq.c.country_id == Country.id)
            .filter(Country.iso3.is_(None))
            .order_by(total.desc(), Country.name)
            .all()
        )

        # ------------------------------------------------------------------
        # Section 1 — all countries with no iso3
        # ------------------------------------------------------------------
        print(f"\n=== 1. Countries with no iso3 ({len(no_iso3)} rows) ===")
        if no_iso3:
            print(f"  {'Name':<60} {'Speeches':>9} {'Votes':>7}")
            print(f"  {'-'*60} {'-'*9} {'-'*7}")
            for name, speeches, votes in no_iso3:
                print(f"  {name:<60} {speeches:>9} {votes:>7}")
        else:
            print("  (none)")

        # ------------------------------------------------------------------
        # Section 2 — unrecognised names (no iso3 + not a known canonical)
        # ------------------------------------------------------------------
        unrecognised = [
            (name, sp, vt)
            for name, sp, vt in no_iso3
            if name.lower() not in _CANONICAL_NAMES
        ]
        print(
            f"\n=== 2. Unrecognised names — no iso3 and not a known canonical"
            f" ({len(unrecognised)} rows) ==="
        )
        print("  Add matching entries to src/extraction/country_aliases.py")
        if unrecognised:
            print(f"  {'Name':<60} {'Speeches':>9} {'Votes':>7}")
            print(f"  {'-'*60} {'-'*9} {'-'*7}")
            for name, speeches, votes in unrecognised:
                print(f"  {name:<60} {speeches:>9} {votes:>7}")
        else:
            print("  (none)")

        # ------------------------------------------------------------------
        # Section 3 — member states missing iso3
        # ------------------------------------------------------------------
        member_no_iso3 = (
            session.query(Country)
            .filter(
                Country.un_member_since.isnot(None),
                Country.iso3.is_(None),
            )
            .order_by(Country.un_member_since, Country.name)
            .all()
        )
        print(
            f"\n=== 3. Member states missing iso3"
            f" ({len(member_no_iso3)} rows) ==="
        )
        if member_no_iso3:
            print(f"  {'Name':<60} {'Member since':>13}")
            print(f"  {'-'*60} {'-'*13}")
            for row in member_no_iso3:
                print(f"  {row.name:<60} {str(row.un_member_since):>13}")
        else:
            print("  (none)")

        # ------------------------------------------------------------------
        # Section 4 — heuristically suspicious names
        # ------------------------------------------------------------------
        _DIGIT_RE = re.compile(r"\d")

        def _heuristic_flags(name: str) -> list[str]:
            flags = []
            if len(name) <= 5:
                flags.append("short")
            if _JUNK_STARTS_NON_LETTER.match(name):
                flags.append("starts-non-letter")
            if _DIGIT_RE.search(name):
                flags.append("has-digit")
            if len(name) > 40:
                flags.append("long")
            return flags

        suspicious = [
            (name, sp, vt, flags)
            for name, sp, vt in no_iso3
            for flags in (_heuristic_flags(name),)
            if flags
        ]
        print(
            f"\n=== 4. Heuristically suspicious names — no iso3"
            f" ({len(suspicious)} rows) ==="
        )
        print("  Flags: short (≤5 chars) | starts-non-letter | has-digit | long (>40 chars)")
        if suspicious:
            print(f"  {'Name':<60} {'Speeches':>9} {'Votes':>7}  Flags")
            print(f"  {'-'*60} {'-'*9} {'-'*7}  -----")
            for name, speeches, votes, flags in suspicious:
                print(
                    f"  {name:<60} {speeches:>9} {votes:>7}  {', '.join(flags)}"
                )
        else:
            print("  (none)")

        print()


def fix_duplicates(
    db_url: str | None = None,
    dry_run: bool = False,
    engine: Engine | None = None,
) -> None:
    if engine is None:
        engine = get_engine(db_url)

    with get_session(engine) as session:
        _delete_junk_rows(session, dry_run)
        renamed, merged = _normalize_existing_rows(session, dry_run)
        f_renamed, f_merged = _fuzzy_merge_no_iso3(session, dry_run)
        renamed += f_renamed
        merged += f_merged
        deleted = _delete_remaining_no_iso3(session, dry_run)

    action = "Would" if dry_run else "Did"
    log.info(
        "%s: merged %d, renamed %d, deleted %d garbage country rows.",
        action, merged, renamed, deleted,
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
    p.add_argument(
        "--report",
        action="store_true",
        help=(
            "Print a data-quality summary (no-iso3 rows, unrecognised names, "
            "member states missing iso3) without making any changes"
        ),
    )
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    if args.report:
        _print_report(db_url=args.db)
        return 0

    fix_duplicates(db_url=args.db, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
