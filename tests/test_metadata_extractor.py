"""Unit tests for src/extraction/metadata_extractor.py."""

from __future__ import annotations

from datetime import date

import pytest

from src.extraction.metadata_extractor import (
    extract_body,
    extract_date,
    extract_location,
    extract_meeting_number,
    extract_president,
    extract_sc_session,
    extract_session,
    extract_symbol,
)


class TestExtractSymbol:
    def test_ga_full(self) -> None:
        assert extract_symbol("A/64/PV.121") == "A/64/PV.121"

    def test_sc_full(self) -> None:
        assert extract_symbol("S/PV.9453") == "S/PV.9453"

    def test_embedded_in_text(self) -> None:
        text = "United Nations  A/76/PV.102  Official Records"
        assert extract_symbol(text) == "A/76/PV.102"

    def test_returns_none_if_absent(self) -> None:
        assert extract_symbol("No symbol here") is None

    @pytest.mark.parametrize(
        "symbol",
        ["A/61/PV.107", "A/76/PV.102", "A/64/PV.121"],
    )
    def test_sample_symbols(self, symbol: str) -> None:
        assert extract_symbol(symbol) == symbol


class TestExtractSession:
    def test_ga_session(self) -> None:
        assert extract_session("A/64/PV.121") == 64

    def test_session_76(self) -> None:
        assert extract_session("A/76/PV.102") == 76

    def test_session_61(self) -> None:
        assert extract_session("A/61/PV.107") == 61

    def test_sc_no_session(self) -> None:
        # SC symbols like S/PV.9453 have no session number in the symbol itself
        assert extract_session("S/PV.9453") is None


class TestExtractScSession:
    @pytest.mark.parametrize(
        "text, expected",
        [
            ("Seventy-third year", 73),
            ("Eighty-first year", 81),
            ("Fifty-second year", 52),
            ("First year", 1),
            ("One hundredth year", 100),
            # space instead of hyphen (OCR variant)
            ("Seventy third year", 73),
            # full SC cover excerpt
            ("Security Council\nSeventy-third year\n8422nd meeting", 73),
        ],
    )
    def test_sc_session_ordinals(self, text: str, expected: int) -> None:
        assert extract_sc_session(text) == expected

    def test_sc_session_missing(self) -> None:
        assert extract_sc_session("no year here") is None


class TestExtractMeetingNumber:
    @pytest.mark.parametrize(
        "text, expected",
        [
            ("121st plenary meeting", 121),
            ("102nd plenary meeting", 102),
            ("107th plenary meeting", 107),
            ("1st plenary meeting", 1),
            ("9453rd plenary meeting", 9453),
        ],
    )
    def test_ordinals(self, text: str, expected: int) -> None:
        assert extract_meeting_number(text) == expected

    def test_embedded(self) -> None:
        text = "General Assembly\n121st plenary meeting\nMonday, 13 September 2010"
        assert extract_meeting_number(text) == 121

    def test_returns_none_if_absent(self) -> None:
        assert extract_meeting_number("No meeting here") is None


class TestExtractDate:
    @pytest.mark.parametrize(
        "text, expected",
        [
            ("Monday, 13 September 2010, 3 p.m.", date(2010, 9, 13)),
            ("Thursday, 8 September 2022, 3 p.m.", date(2022, 9, 8)),
            ("Thursday, 13 September 2007, 10 a.m.", date(2007, 9, 13)),
            ("1 January 2000", date(2000, 1, 1)),
            ("31 December 1999", date(1999, 12, 31)),
        ],
    )
    def test_various_dates(self, text: str, expected: date) -> None:
        assert extract_date(text) == expected

    def test_returns_none_if_absent(self) -> None:
        assert extract_date("No date in this text") is None

    def test_rejects_implausible_year(self) -> None:
        assert extract_date("1 January 1944") is None
        assert extract_date("1 January 2101") is None

    def test_accepts_boundary_years(self) -> None:
        from datetime import date as _date

        assert extract_date("24 October 1945") == _date(1945, 10, 24)
        assert extract_date("31 December 2100") == _date(2100, 12, 31)


class TestExtractLocation:
    def test_new_york(self) -> None:
        assert (
            extract_location("Monday, 13 September 2010, 3 p.m.\nNew York")
            == "New York"
        )

    def test_geneva(self) -> None:
        assert extract_location("Meeting held in Geneva") == "Geneva"

    def test_returns_none(self) -> None:
        assert extract_location("Vienna") is None

    def test_location_with_following_text(self) -> None:
        # Location followed by other content on the page is still found
        header = (
            "Security Council\nSeventy-third year\n8422nd meeting\n"
            "Thursday, 13 December 2018\nNew York\nProvisional"
        )
        assert extract_location(header) == "New York"


class TestExtractPresident:
    def test_full_president_line(self) -> None:
        text = (
            "President:  Mr. Ali Abdussalam Treki .......... (Libyan Arab Jamahiriya)"
        )
        result = extract_president(text)
        assert result is not None
        assert "Treki" in result.name
        assert result.country == "Libyan Arab Jamahiriya"

    def test_female_president(self) -> None:
        text = "President:  Ms. Al-Khalifa ............................. (Bahrain)"
        result = extract_president(text)
        assert result is not None
        assert result.country == "Bahrain"

    def test_shahid(self) -> None:
        text = (
            "President:  Mr. Shahid "
            "............................................... (Maldives)"
        )
        result = extract_president(text)
        assert result is not None
        assert result.country == "Maldives"

    def test_returns_none_if_absent(self) -> None:
        assert extract_president("No president line here") is None


class TestExtractBody:
    def test_ga(self) -> None:
        assert extract_body("A/64/PV.121") == "GA"

    def test_sc(self) -> None:
        assert extract_body("S/PV.9453") == "SC"
