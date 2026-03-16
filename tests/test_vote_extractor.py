"""Unit tests for src/extraction/vote_extractor.py."""

from __future__ import annotations


from src.extraction.vote_extractor import (
    _extract_country_votes,
    _extract_vote_totals,
    _parse_country_list,
    extract_resolution_from_adoption,
)
from src.models import FormattedSegment, TextBlock


def _make_block(text: str, page_num: int = 1) -> TextBlock:
    return TextBlock(
        segments=[FormattedSegment(text=text, bold=False, italic=True)],
        page_num=page_num,
        y0=100.0,
        x0=50.0,
    )


class TestParseCountryList:
    def test_simple_list(self) -> None:
        result = _parse_country_list("Algeria, Angola, Argentina")
        assert result == ["Algeria", "Angola", "Argentina"]

    def test_strips_whitespace(self) -> None:
        result = _parse_country_list("  France ,  Germany , Italy  ")
        assert "France" in result
        assert "Germany" in result

    def test_removes_trailing_period(self) -> None:
        result = _parse_country_list("France, Germany.")
        assert "Germany" in result
        assert "." not in result[-1]

    def test_single_country(self) -> None:
        result = _parse_country_list("United States of America")
        assert result == ["United States of America"]

    def test_empty(self) -> None:
        result = _parse_country_list("")
        assert result == []


class TestExtractVoteTotals:
    def test_standard_format(self) -> None:
        text = "adopted by 121 votes to 5, with 3 abstentions"
        yes, no, abstain = _extract_vote_totals(text)
        assert yes == 121
        assert no == 5
        assert abstain == 3

    def test_alt_format(self) -> None:
        text = "14 votes in favour to 0 against, with 1 abstention"
        yes, no, abstain = _extract_vote_totals(text)
        assert yes == 14
        assert no == 0
        assert abstain == 1

    def test_no_abstentions(self) -> None:
        text = "100 in favour to 0 against"
        yes, no, _ = _extract_vote_totals(text)
        assert yes == 100
        assert no == 0

    def test_returns_none_tuple_if_absent(self) -> None:
        yes, no, abstain = _extract_vote_totals("It was so decided.")
        assert yes is None
        assert no is None
        assert abstain is None


class TestExtractCountryVotes:
    def test_basic_extraction(self) -> None:
        blocks = [
            _make_block("In favour: Algeria, Angola, Argentina"),
            _make_block("Against: Israel, United States of America"),
            _make_block("Abstaining: Australia, Canada"),
        ]
        votes = _extract_country_votes(blocks)
        positions = {cv.country: cv.vote_position for cv in votes}
        assert positions["Algeria"] == "yes"
        assert positions["Israel"] == "no"
        assert positions["Australia"] == "abstain"
        assert positions["United States of America"] == "no"

    def test_empty_blocks(self) -> None:
        assert _extract_country_votes([]) == []

    def test_consensus_has_no_country_votes(self) -> None:
        blocks = [_make_block("It was so decided.")]
        assert _extract_country_votes(blocks) == []


class TestExtractResolutionFromAdoption:
    def test_consensus_adoption(self) -> None:
        text = "Draft resolution A/64/L.72 was adopted (resolution 64/299)."
        res = extract_resolution_from_adoption(text, [])
        assert res is not None
        assert res.draft_symbol == "A/64/L.72"
        assert res.adopted_symbol == "64/299"
        assert res.vote_type == "consensus"
        assert res.yes_count is None

    def test_decision_adoption(self) -> None:
        text = "Draft decision A/76/L.79 was adopted (decision 76/575)."
        res = extract_resolution_from_adoption(text, [])
        assert res is not None
        assert res.draft_symbol == "A/76/L.79"
        assert res.adopted_symbol == "76/575"

    def test_oral_correction(self) -> None:
        text = "Draft decision A/64/L.71, as orally corrected, was adopted."
        res = extract_resolution_from_adoption(text, [])
        assert res is not None
        assert res.draft_symbol == "A/64/L.71"
        assert res.adopted_symbol is None

    def test_recorded_vote(self) -> None:
        surrounding = [
            _make_block("adopted by 121 votes to 5, with 3 abstentions"),
            _make_block("In favour: Algeria, Angola"),
            _make_block("Against: Israel, USA"),
            _make_block("Abstaining: Australia"),
        ]
        text = "Draft resolution A/64/L.47 was adopted."
        res = extract_resolution_from_adoption(text, surrounding)
        assert res is not None
        assert res.vote_type == "recorded"
        assert res.yes_count == 121
        assert res.no_count == 5
        assert res.abstain_count == 3
        assert any(cv.country == "Algeria" for cv in res.country_votes)

    def test_returns_none_for_non_adoption(self) -> None:
        assert extract_resolution_from_adoption("It was so decided.", []) is None

    def test_roman_numeral_adoption(self) -> None:
        text = "Draft resolution I was adopted (resolution 65/206)."
        res = extract_resolution_from_adoption(text, [])
        assert res is not None
        assert res.draft_symbol == "I"
        assert res.adopted_symbol == "65/206"
        assert res.vote_type == "consensus"

    def test_roman_numeral_adoption_no_symbol(self) -> None:
        text = "Draft resolution XIX was adopted."
        res = extract_resolution_from_adoption(text, [])
        assert res is not None
        assert res.draft_symbol == "XIX"
        assert res.adopted_symbol is None

    def test_amendment_adoption_recorded(self) -> None:
        surrounding = [
            _make_block("adopted by 10 votes to 2, with 1 abstention"),
            _make_block("In favour: France, Germany, Spain"),
            _make_block("Against: Israel, USA"),
            _make_block("Abstaining: Australia"),
        ]
        text = (
            "The amendment (A/65/L.53) was adopted by 10 votes to 2, with 1 abstention."
        )
        res = extract_resolution_from_adoption(text, surrounding)
        assert res is not None
        assert res.draft_symbol == "A/65/L.53"
        assert res.vote_type == "recorded"
        assert res.yes_count == 10
        assert res.no_count == 2
        assert res.abstain_count == 1

    def test_recorded_vote_signal_newer_format(self) -> None:
        """Country lists appear *before* the adoption line (newer PDF format)."""
        signal_block = _make_block("A recorded vote was taken.")
        country_blocks = [
            _make_block("In favour: Algeria, Angola, Argentina"),
            _make_block("Against: Israel"),
            _make_block("Abstaining: Australia"),
        ]
        # adoption line comes after; surrounding = signal + country blocks
        surrounding = [signal_block] + country_blocks
        text = (
            "Draft resolution A/65/L.71 was adopted by 120 votes to 1,"
            " with 5 abstentions."
        )
        res = extract_resolution_from_adoption(text, surrounding)
        assert res is not None
        assert res.vote_type == "recorded"
        assert res.yes_count == 120
        assert res.no_count == 1
        assert res.abstain_count == 5
        positions = {cv.country: cv.vote_position for cv in res.country_votes}
        assert positions["Algeria"] == "yes"
        assert positions["Israel"] == "no"
        assert positions["Australia"] == "abstain"

    def test_preceding_text_resolves_unknown_symbol(self) -> None:
        """When adoption line has no symbol, preceding_text provides it."""
        text = "The draft resolution was adopted."
        res = extract_resolution_from_adoption(
            text, [], preceding_text="Draft resolution (A/65/L.99)"
        )
        assert res is not None
        assert res.draft_symbol == "A/65/L.99"
