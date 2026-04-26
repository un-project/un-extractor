"""Unit and integration tests for scripts/tag_speech_types.py."""

from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.tag_speech_types import _ensure_column, tag_speeches  # noqa: E402
from src.db.database import create_schema  # noqa: E402
from src.db.models import (  # noqa: E402
    Country,
    Document,
    DocumentItem,
    Resolution,
    Speaker,
    Speech,
    Vote,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    create_schema(engine)
    with Session(engine) as s:
        _ensure_column(s)
        yield s


def _make_doc(s: Session, body: str = "GA") -> Document:
    doc = Document(
        symbol="A/64/PV.1" if body == "GA" else "S/PV.1",
        body=body,
        meeting_number=1,
        date=date(2009, 9, 1),
        location="New York",
    )
    s.add(doc)
    s.flush()
    return doc


def _make_item(s: Session, doc: Document, position: int = 0) -> DocumentItem:
    item = DocumentItem(
        document_id=doc.id,
        position=position,
        item_type="agenda_item",
        title="Test item",
    )
    s.add(item)
    s.flush()
    return item


def _make_speaker(s: Session, name: str, role: str | None = None) -> Speaker:
    sp = Speaker(name=name, role=role)
    s.add(sp)
    s.flush()
    return sp


def _make_country_speaker(s: Session, country_name: str, speaker_name: str) -> Speaker:
    c = Country(name=country_name)
    s.add(c)
    s.flush()
    sp = Speaker(name=speaker_name, country_id=c.id)
    s.add(sp)
    s.flush()
    return sp


def _make_speech(
    s: Session,
    doc: Document,
    item: DocumentItem,
    speaker: Speaker,
    pos: int,
) -> Speech:
    speech = Speech(
        document_id=doc.id,
        item_id=item.id,
        speaker_id=speaker.id,
        text="Some text.",
        position_in_document=pos,
        position_in_item=pos,
    )
    s.add(speech)
    s.flush()
    return speech


def _make_resolution(s: Session) -> Resolution:
    res = Resolution(draft_symbol="A/64/L.1", body="GA")
    s.add(res)
    s.flush()
    return res


def _make_vote(
    s: Session,
    doc: Document,
    item: DocumentItem,
    resolution: Resolution,
    vote_type: str,
    pos: int,
) -> Vote:
    v = Vote(
        document_id=doc.id,
        item_id=item.id,
        resolution_id=resolution.id,
        vote_type=vote_type,
        vote_scope="whole_resolution",
        position_in_item=pos,
    )
    s.add(v)
    s.flush()
    return v


# ---------------------------------------------------------------------------
# Tests — substantive (default)
# ---------------------------------------------------------------------------


class TestSubstantive:
    def test_all_speeches_default_to_substantive(self, session):
        doc = _make_doc(session)
        item = _make_item(session, doc)
        sp = _make_speaker(session, "Smith")
        _make_speech(session, doc, item, sp, pos=0)
        _make_speech(session, doc, item, sp, pos=1)

        counts = tag_speeches(session)
        assert counts.get("substantive", 0) == 2
        assert counts.get("explanation_of_vote", 0) == 0
        assert counts.get("procedural", 0) == 0

    def test_speeches_without_item_are_substantive(self, session):
        doc = _make_doc(session)
        _make_item(session, doc)
        sp = _make_speaker(session, "Jones")
        speech = Speech(
            document_id=doc.id,
            item_id=None,  # no item
            speaker_id=sp.id,
            text="Some text.",
            position_in_document=0,
            position_in_item=0,
        )
        session.add(speech)
        session.flush()

        counts = tag_speeches(session)
        assert counts.get("substantive", 0) == 1


# ---------------------------------------------------------------------------
# Tests — explanation_of_vote
# ---------------------------------------------------------------------------


class TestExplanationOfVote:
    def test_post_vote_speech_tagged_eov(self, session):
        doc = _make_doc(session)
        item = _make_item(session, doc)
        res = _make_resolution(session)
        sp = _make_speaker(session, "Brown")

        _make_speech(session, doc, item, sp, pos=0)  # substantive (before vote)
        _make_vote(session, doc, item, res, "recorded", pos=1)
        eov = _make_speech(session, doc, item, sp, pos=2)  # EOV (after vote)

        counts = tag_speeches(session)
        assert counts.get("explanation_of_vote", 0) == 1
        assert counts.get("substantive", 0) == 1

        session.refresh(eov)
        assert eov.speech_type == "explanation_of_vote"

    def test_pre_vote_speech_is_substantive(self, session):
        doc = _make_doc(session)
        item = _make_item(session, doc)
        res = _make_resolution(session)
        sp = _make_speaker(session, "White")

        pre = _make_speech(session, doc, item, sp, pos=0)
        _make_vote(session, doc, item, res, "recorded", pos=1)
        _make_speech(session, doc, item, sp, pos=2)

        tag_speeches(session)
        session.refresh(pre)
        assert pre.speech_type == "substantive"

    def test_consensus_vote_does_not_trigger_eov(self, session):
        doc = _make_doc(session)
        item = _make_item(session, doc)
        res = _make_resolution(session)
        sp = _make_speaker(session, "Green")

        _make_speech(session, doc, item, sp, pos=0)
        _make_vote(session, doc, item, res, "consensus", pos=1)
        post = _make_speech(session, doc, item, sp, pos=2)

        tag_speeches(session)
        session.refresh(post)
        # Consensus vote does not trigger EOV tagging
        assert post.speech_type == "substantive"

    def test_multiple_post_vote_speeches_all_tagged(self, session):
        doc = _make_doc(session)
        item = _make_item(session, doc)
        res = _make_resolution(session)
        sp = _make_speaker(session, "Black")

        _make_vote(session, doc, item, res, "recorded", pos=0)
        speeches = [_make_speech(session, doc, item, sp, pos=i + 1) for i in range(4)]

        tag_speeches(session)
        for sp_obj in speeches:
            session.refresh(sp_obj)
            assert sp_obj.speech_type == "explanation_of_vote"


# ---------------------------------------------------------------------------
# Tests — procedural
# ---------------------------------------------------------------------------


class TestProcedural:
    def test_the_president_is_procedural(self, session):
        doc = _make_doc(session)
        item = _make_item(session, doc)
        president = _make_speaker(session, "The President")
        sp = _make_speech(session, doc, item, president, pos=0)

        tag_speeches(session)
        session.refresh(sp)
        assert sp.speech_type == "procedural"

    def test_the_secretary_general_is_procedural(self, session):
        doc = _make_doc(session)
        item = _make_item(session, doc)
        sg = _make_speaker(session, "The Secretary-General")
        sp = _make_speech(session, doc, item, sg, pos=0)

        tag_speeches(session)
        session.refresh(sp)
        assert sp.speech_type == "procedural"

    def test_role_chairman_is_procedural(self, session):
        doc = _make_doc(session)
        item = _make_item(session, doc)
        chair = _make_speaker(session, "SomeName", role="Chairman")
        sp = _make_speech(session, doc, item, chair, pos=0)

        tag_speeches(session)
        session.refresh(sp)
        assert sp.speech_type == "procedural"

    def test_regular_delegate_is_not_procedural(self, session):
        doc = _make_doc(session)
        item = _make_item(session, doc)
        delegate = _make_speaker(session, "Smith")
        sp = _make_speech(session, doc, item, delegate, pos=0)

        tag_speeches(session)
        session.refresh(sp)
        assert sp.speech_type == "substantive"

    def test_procedural_overrides_eov(self, session):
        """President speaking after a recorded vote → procedural, not EOV."""
        doc = _make_doc(session)
        item = _make_item(session, doc)
        res = _make_resolution(session)
        president = _make_speaker(session, "The President")

        _make_vote(session, doc, item, res, "recorded", pos=0)
        sp = _make_speech(session, doc, item, president, pos=1)

        tag_speeches(session)
        session.refresh(sp)
        assert sp.speech_type == "procedural"


# ---------------------------------------------------------------------------
# Tests — body filter
# ---------------------------------------------------------------------------


class TestBodyFilter:
    def test_body_filter_ga_only(self, session):
        ga_doc = _make_doc(session, body="GA")
        sc_doc = Document(
            symbol="S/PV.1",
            body="SC",
            meeting_number=1,
            date=date(2009, 9, 1),
            location="New York",
        )
        session.add(sc_doc)
        session.flush()
        sc_item = _make_item(session, sc_doc)

        ga_item = _make_item(session, ga_doc)
        sp = _make_speaker(session, "Smith")

        ga_speech = _make_speech(session, ga_doc, ga_item, sp, pos=0)
        sc_speech = _make_speech(session, sc_doc, sc_item, sp, pos=0)

        # Only tag GA speeches
        tag_speeches(session, body="GA")

        session.refresh(ga_speech)
        session.refresh(sc_speech)
        assert ga_speech.speech_type == "substantive"
        assert sc_speech.speech_type is None  # untouched


# ---------------------------------------------------------------------------
# Tests — dry run
# ---------------------------------------------------------------------------


class TestDryRun:
    def test_dry_run_returns_counts_without_writing(self, session):
        doc = _make_doc(session)
        item = _make_item(session, doc)
        res = _make_resolution(session)
        president = _make_speaker(session, "The President")
        delegate = _make_speaker(session, "Smith")

        _make_speech(session, doc, item, delegate, pos=0)  # substantive
        _make_vote(session, doc, item, res, "recorded", pos=1)
        eov_sp = _make_speech(session, doc, item, delegate, pos=2)  # EOV
        proc_sp = _make_speech(session, doc, item, president, pos=3)  # procedural

        counts = tag_speeches(session, dry_run=True)
        assert counts["explanation_of_vote"] >= 1
        assert counts["procedural"] >= 1

        # No changes written
        session.refresh(eov_sp)
        assert eov_sp.speech_type is None
        session.refresh(proc_sp)
        assert proc_sp.speech_type is None
