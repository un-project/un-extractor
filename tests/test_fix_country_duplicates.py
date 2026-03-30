"""Tests for scripts/fix_country_duplicates.py using an in-memory SQLite database.

Covers:
- Alias rename in-place (no canonical row yet)
- Merge with iso3 transfer (alias has iso3, canonical does not)
- Merge where canonical already has iso3 (canonical's iso3 is preserved)
- Speaker move: alias speaker reassigned to canonical country
- Speaker deduplication: speeches redirected to canonical speaker, alias speaker deleted
- CountryVote move: alias vote reassigned to canonical country
- CountryVote deduplication: duplicate dropped, canonical kept
- Junk row deletion: blank, sentinel, named, too-long, pattern-based
- Junk deletion detaches speakers before removing country row
- Savepoint rollback: a failed row is skipped, other rows are still processed
- dry_run=True: no changes applied to the database
"""

from __future__ import annotations

from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

from scripts.fix_country_duplicates import _delete_junk_rows, _normalize_existing_rows
from src.db.database import create_schema, get_session
from src.db.models import (
    Country,
    CountryVote,
    Document,
    Resolution,
    Speaker,
    Speech,
    Vote,
)

# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------


def _engine() -> Engine:
    e = create_engine("sqlite:///:memory:")
    create_schema(e)
    return e


def _country(session, name: str, iso3: str | None = None) -> Country:
    c = Country(name=name, iso3=iso3)
    session.add(c)
    session.flush()
    return c


def _speaker(session, country: Country, name: str = "Mr. Smith") -> Speaker:
    spk = Speaker(name=name, country_id=country.id)
    session.add(spk)
    session.flush()
    return spk


def _document(session, symbol: str = "S/PV.1") -> Document:
    doc = Document(symbol=symbol, body="SC", meeting_number=1)
    session.add(doc)
    session.flush()
    return doc


def _resolution(session, draft: str = "S/RES/1") -> Resolution:
    res = Resolution(draft_symbol=draft, body="SC")
    session.add(res)
    session.flush()
    return res


def _vote(session, doc: Document, res: Resolution) -> Vote:
    v = Vote(
        document_id=doc.id,
        resolution_id=res.id,
        vote_type="recorded",
        vote_scope="whole_resolution",
    )
    session.add(v)
    session.flush()
    return v


def _speech(session, doc: Document, spk: Speaker) -> Speech:
    s = Speech(
        document_id=doc.id,
        speaker_id=spk.id,
        text="Test speech.",
        position_in_document=0,
    )
    session.add(s)
    session.flush()
    return s


def _country_vote(
    session, vote: Vote, country: Country, position: str = "yes"
) -> CountryVote:
    cv = CountryVote(vote_id=vote.id, country_id=country.id, vote_position=position)
    session.add(cv)
    session.flush()
    return cv


# ---------------------------------------------------------------------------
# Rename in-place (no canonical row exists yet)
# ---------------------------------------------------------------------------


class TestRenameInPlace:
    def test_alias_renamed_to_canonical(self) -> None:
        engine = _engine()
        with get_session(engine) as session:
            _country(session, "Austalia")  # alias → "Australia"
            _normalize_existing_rows(session, dry_run=False)

        with get_session(engine) as session:
            assert session.query(Country).filter_by(name="Australia").count() == 1
            assert session.query(Country).filter_by(name="Austalia").count() == 0

    def test_unknown_name_left_unchanged(self) -> None:
        engine = _engine()
        with get_session(engine) as session:
            _country(session, "France")  # not an alias key; should stay as-is
            _normalize_existing_rows(session, dry_run=False)

        with get_session(engine) as session:
            assert session.query(Country).filter_by(name="France").count() == 1


# ---------------------------------------------------------------------------
# Merge — iso3 handling
# ---------------------------------------------------------------------------


class TestMergeIso3:
    def test_iso3_transferred_when_canonical_has_none(self) -> None:
        """Alias's iso3 is moved to the canonical row when canonical has none."""
        engine = _engine()
        with get_session(engine) as session:
            _country(session, "Austalia", iso3="AUS")
            _country(session, "Australia", iso3=None)
            _normalize_existing_rows(session, dry_run=False)

        with get_session(engine) as session:
            canonical = session.query(Country).filter_by(name="Australia").one()
            assert canonical.iso3 == "AUS"
            assert session.query(Country).filter_by(name="Austalia").first() is None

    def test_canonical_iso3_preserved_when_already_set(self) -> None:
        """Canonical's own iso3 is not overwritten by the alias's iso3."""
        engine = _engine()
        with get_session(engine) as session:
            _country(session, "Russia", iso3="RUS")  # alias → "Russian Federation"
            _country(session, "Russian Federation", iso3="SUN")
            _normalize_existing_rows(session, dry_run=False)

        with get_session(engine) as session:
            canonical = (
                session.query(Country).filter_by(name="Russian Federation").one()
            )
            assert canonical.iso3 == "SUN"
            assert session.query(Country).filter_by(name="Russia").first() is None


# ---------------------------------------------------------------------------
# Merge — speakers
# ---------------------------------------------------------------------------


class TestMergeSpeakers:
    def test_speaker_moved_to_canonical_country(self) -> None:
        engine = _engine()
        with get_session(engine) as session:
            alias = _country(session, "Austalia")
            canonical = _country(session, "Australia")
            spk = _speaker(session, alias)
            _normalize_existing_rows(session, dry_run=False)

        with get_session(engine) as session:
            canonical = session.query(Country).filter_by(name="Australia").one()
            spk = session.query(Speaker).filter_by(name="Mr. Smith").one()
            assert spk.country_id == canonical.id

    def test_duplicate_speaker_speeches_redirected_and_alias_deleted(self) -> None:
        """When both alias and canonical have the same-named speaker, speeches
        are moved to the canonical speaker and the alias speaker is removed."""
        engine = _engine()
        with get_session(engine) as session:
            alias = _country(session, "Austalia")
            canonical = _country(session, "Australia")
            alias_spk = _speaker(session, alias, name="Mr. Jones")
            canonical_spk = _speaker(session, canonical, name="Mr. Jones")
            doc = _document(session)
            _speech(session, doc, alias_spk)
            _normalize_existing_rows(session, dry_run=False)

        with get_session(engine) as session:
            canonical_spk = (
                session.query(Speaker)
                .join(Country)
                .filter(Country.name == "Australia", Speaker.name == "Mr. Jones")
                .one()
            )
            # Speech should now belong to the canonical speaker
            s = session.query(Speech).one()
            assert s.speaker_id == canonical_spk.id
            # Alias speaker should be gone
            assert session.query(Speaker).count() == 1


# ---------------------------------------------------------------------------
# Merge — country votes
# ---------------------------------------------------------------------------


class TestMergeCountryVotes:
    def _setup_vote(self, session) -> Vote:
        doc = _document(session)
        res = _resolution(session)
        return _vote(session, doc, res)

    def test_country_vote_moved_to_canonical(self) -> None:
        engine = _engine()
        with get_session(engine) as session:
            alias = _country(session, "Austalia")
            canonical = _country(session, "Australia")
            vote = self._setup_vote(session)
            _country_vote(session, vote, alias)
            _normalize_existing_rows(session, dry_run=False)

        with get_session(engine) as session:
            canonical = session.query(Country).filter_by(name="Australia").one()
            cv = session.query(CountryVote).one()
            assert cv.country_id == canonical.id

    def test_duplicate_country_vote_dropped(self) -> None:
        """When both alias and canonical already have a vote for the same Vote
        row, the alias's duplicate is deleted."""
        engine = _engine()
        with get_session(engine) as session:
            alias = _country(session, "Austalia")
            canonical = _country(session, "Australia")
            vote = self._setup_vote(session)
            _country_vote(session, vote, alias, position="yes")
            _country_vote(session, vote, canonical, position="yes")
            _normalize_existing_rows(session, dry_run=False)

        with get_session(engine) as session:
            assert session.query(CountryVote).count() == 1
            canonical = session.query(Country).filter_by(name="Australia").one()
            assert session.query(CountryVote).one().country_id == canonical.id


# ---------------------------------------------------------------------------
# Junk row deletion
# ---------------------------------------------------------------------------


class TestDeleteJunkRows:
    def test_deletes_empty_name(self) -> None:
        engine = _engine()
        with get_session(engine) as session:
            _country(session, "")
            _delete_junk_rows(session, dry_run=False)

        with get_session(engine) as session:
            assert session.query(Country).filter_by(name="").count() == 0

    def test_deletes_sentinel_none(self) -> None:
        engine = _engine()
        with get_session(engine) as session:
            _country(session, "None")
            _delete_junk_rows(session, dry_run=False)

        with get_session(engine) as session:
            assert session.query(Country).filter_by(name="None").count() == 0

    def test_deletes_named_junk(self) -> None:
        """Entries from the hardcoded junk list are removed."""
        engine = _engine()
        with get_session(engine) as session:
            _country(session, "Aviva")
            _delete_junk_rows(session, dry_run=False)

        with get_session(engine) as session:
            assert session.query(Country).filter_by(name="Aviva").count() == 0

    def test_deletes_name_over_100_chars(self) -> None:
        engine = _engine()
        long_name = "x" * 101
        with get_session(engine) as session:
            _country(session, long_name)
            _delete_junk_rows(session, dry_run=False)

        with get_session(engine) as session:
            assert session.query(Country).filter_by(name=long_name).count() == 0

    def test_deletes_starts_with_non_letter_when_no_iso3(self) -> None:
        engine = _engine()
        with get_session(engine) as session:
            _country(session, "(C)")  # starts with "("
            _delete_junk_rows(session, dry_run=False)

        with get_session(engine) as session:
            assert session.query(Country).filter_by(name="(C)").count() == 0

    def test_preserves_non_letter_start_when_iso3_is_set(self) -> None:
        """A row with an iso3 code is never deleted by pattern matching."""
        engine = _engine()
        with get_session(engine) as session:
            _country(session, "(C)", iso3="XYZ")
            _delete_junk_rows(session, dry_run=False)

        with get_session(engine) as session:
            assert session.query(Country).filter_by(name="(C)").count() == 1

    def test_deletes_procedural_text_fragment(self) -> None:
        engine = _engine()
        with get_session(engine) as session:
            _country(session, "I shall put to the vote")
            _delete_junk_rows(session, dry_run=False)

        with get_session(engine) as session:
            assert (
                session.query(Country).filter_by(name="I shall put to the vote").count()
            ) == 0

    def test_detaches_speakers_before_deleting_junk_country(self) -> None:
        """Speakers linked to a junk country row get country_id set to NULL
        rather than being deleted."""
        engine = _engine()
        with get_session(engine) as session:
            junk = _country(session, "None")
            spk = _speaker(session, junk)
            _delete_junk_rows(session, dry_run=False)

        with get_session(engine) as session:
            assert session.query(Country).filter_by(name="None").count() == 0
            spk = session.query(Speaker).one()
            assert spk.country_id is None


# ---------------------------------------------------------------------------
# Savepoint rollback on error
# ---------------------------------------------------------------------------


class TestSavepointRollback:
    def test_failed_row_skipped_others_still_processed(self) -> None:
        """When merging one row raises an exception the savepoint rolls back
        that row only; other rows in the same run are still processed."""
        engine = _engine()
        with get_session(engine) as session:
            # "Russia" has no canonical yet → will be *renamed* (no delete)
            _country(session, "Russia")
            # "Austalia" + "Australia" → merge (delete "Austalia")
            _country(session, "Austalia")
            _country(session, "Australia")

        with get_session(engine) as session:
            original_delete = session.delete

            def _fail_for_austalia(obj):
                if isinstance(obj, Country) and obj.name == "Austalia":
                    raise ValueError("injected failure")
                return original_delete(obj)

            with patch.object(session, "delete", side_effect=_fail_for_austalia):
                _normalize_existing_rows(session, dry_run=False)

        with get_session(engine) as session:
            # Rename succeeded: "Russia" → "Russian Federation"
            assert (
                session.query(Country).filter_by(name="Russian Federation").count() == 1
            )
            assert session.query(Country).filter_by(name="Russia").count() == 0
            # Merge failed (savepoint rolled back): "Austalia" still present
            assert session.query(Country).filter_by(name="Austalia").count() == 1
            assert session.query(Country).filter_by(name="Australia").count() == 1


# ---------------------------------------------------------------------------
# Dry-run flag
# ---------------------------------------------------------------------------


class TestDryRun:
    def test_dry_run_does_not_rename(self) -> None:
        engine = _engine()
        with get_session(engine) as session:
            _country(session, "Austalia")
            _normalize_existing_rows(session, dry_run=True)

        with get_session(engine) as session:
            assert session.query(Country).filter_by(name="Austalia").count() == 1
            assert session.query(Country).filter_by(name="Australia").count() == 0

    def test_dry_run_does_not_merge(self) -> None:
        engine = _engine()
        with get_session(engine) as session:
            _country(session, "Russia")
            _country(session, "Russian Federation")
            _normalize_existing_rows(session, dry_run=True)

        with get_session(engine) as session:
            assert session.query(Country).filter_by(name="Russia").count() == 1
            assert (
                session.query(Country).filter_by(name="Russian Federation").count() == 1
            )

    def test_dry_run_does_not_delete_junk(self) -> None:
        engine = _engine()
        with get_session(engine) as session:
            _country(session, "None")
            _delete_junk_rows(session, dry_run=True)

        with get_session(engine) as session:
            assert session.query(Country).filter_by(name="None").count() == 1
