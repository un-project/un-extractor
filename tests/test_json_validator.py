"""Unit tests for src/validation/json_validator.py."""

from __future__ import annotations

from datetime import date

import pytest

from src.models import (
    CountryVote,
    DocumentItem,
    MeetingRecord,
    PresidentInfo,
    Resolution,
    Speech,
    SpeakerInfo,
    StageDirection,
)
from src.validation.json_validator import ValidationError, _check_resolution, validate_record


def _make_resolution(draft_symbol: str = "A/64/L.72", vote_type: str = "consensus") -> Resolution:
    return Resolution(
        draft_symbol=draft_symbol,
        vote_type=vote_type,
        yes_count=None,
        no_count=None,
        abstain_count=None,
        country_votes=[],
    )


def _make_record(**overrides) -> MeetingRecord:
    defaults: dict = dict(
        symbol="A/64/PV.121",
        body="GA",
        session=64,
        meeting_number=121,
        date=date(2010, 9, 13),
        location="New York",
        president=PresidentInfo(name="Mr. Treki", country="Libya"),
        items=[],
    )
    defaults.update(overrides)
    return MeetingRecord(**defaults)


class TestCheckResolution:
    def test_valid_l_series(self) -> None:
        errors = _check_resolution(_make_resolution("A/64/L.72"), "items[0].resolutions[0]")
        assert errors == []

    def test_valid_sc_symbol(self) -> None:
        errors = _check_resolution(_make_resolution("S/2021/L.1"), "x")
        assert errors == []

    def test_roman_numeral_I(self) -> None:
        errors = _check_resolution(_make_resolution("I"), "x")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_roman_numeral_XIX(self) -> None:
        errors = _check_resolution(_make_resolution("XIX"), "x")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_roman_numeral_VIII(self) -> None:
        errors = _check_resolution(_make_resolution("VIII"), "x")
        assert errors == []

    def test_roman_numeral_V(self) -> None:
        errors = _check_resolution(_make_resolution("V"), "x")
        assert errors == []

    def test_roman_numeral_X(self) -> None:
        errors = _check_resolution(_make_resolution("X"), "x")
        assert errors == []

    def test_unknown_symbol_flagged(self) -> None:
        errors = _check_resolution(_make_resolution("unknown"), "x")
        assert len(errors) == 1
        assert "unexpected format" in errors[0].message

    def test_recorded_vote_requires_counts(self) -> None:
        res = Resolution(
            draft_symbol="A/64/L.47",
            vote_type="recorded",
            yes_count=None,
            no_count=5,
            abstain_count=0,
            country_votes=[],
        )
        errors = _check_resolution(res, "x")
        assert any("yes_count" in e.field for e in errors)

    def test_recorded_vote_valid(self) -> None:
        res = Resolution(
            draft_symbol="A/64/L.47",
            vote_type="recorded",
            yes_count=121,
            no_count=5,
            abstain_count=3,
            country_votes=[CountryVote(country="France", vote_position="yes")],
        )
        errors = _check_resolution(res, "x")
        assert errors == []


class TestValidateRecord:
    def test_valid_record(self) -> None:
        assert validate_record(_make_record()) == []

    def test_missing_symbol(self) -> None:
        from src.validation.json_validator import _check_symbol
        errors = _check_symbol(None)
        assert any(e.field == "symbol" for e in errors)

    def test_missing_date(self) -> None:
        from src.validation.json_validator import _check_date
        errors = _check_date(None)
        assert any(e.field == "date" for e in errors)

    def test_missing_location(self) -> None:
        errors = validate_record(_make_record(location=""))
        assert any(e.field == "location" for e in errors)

    def test_roman_numeral_resolution_in_record(self) -> None:
        item = DocumentItem(
            position=0,
            item_type="agenda_item",
            title="Test",
            resolutions=[_make_resolution("XIV")],
        )
        record = _make_record(items=[item])
        errors = validate_record(record)
        assert not any("draft_symbol" in e.field for e in errors)
