"""Unit tests for src/extraction/speaker_extractor.py."""

from __future__ import annotations


from src.extraction.speaker_extractor import (
    _split_attribution_and_body,
    parse_speaker_info,
)


class TestParseSpeakerInfo:
    def test_mr_with_country(self) -> None:
        info = parse_speaker_info("Mr. Alsaidi (Yemen):")
        assert info is not None
        assert "Alsaidi" in info.name
        assert info.country == "Yemen"
        assert info.language is None

    def test_mrs_with_country(self) -> None:
        info = parse_speaker_info("Mrs. Salazar-Mejía (Colombia) (spoke in Spanish):")
        assert info is not None
        assert "Salazar" in info.name
        assert info.country == "Colombia"
        assert info.language == "Spanish"

    def test_ms_with_country(self) -> None:
        info = parse_speaker_info("Ms. Carlson (Dominican Republic):")
        assert info is not None
        assert info.country == "Dominican Republic"

    def test_spoke_in_arabic(self) -> None:
        info = parse_speaker_info("Mr. Al Hassan (Oman) (spoke in Arabic):")
        assert info is not None
        assert info.language == "Arabic"

    def test_spoke_in_chinese(self) -> None:
        info = parse_speaker_info("Mr. Dai Bing (China) (spoke in Chinese):")
        assert info is not None
        assert info.country == "China"
        assert info.language == "Chinese"

    def test_the_president_no_country(self) -> None:
        info = parse_speaker_info("The President:")
        assert info is not None
        assert info.country is None
        assert "President" in info.name

    def test_the_president_spoke_in_arabic(self) -> None:
        info = parse_speaker_info("The President (spoke in Arabic):")
        assert info is not None
        assert info.country is None
        assert info.language == "Arabic"

    def test_secretary_general(self) -> None:
        info = parse_speaker_info("The Secretary-General:")
        assert info is not None
        assert info.country is None

    def test_special_chars_in_name(self) -> None:
        info = parse_speaker_info("Mr. Kaludjerović (Montenegro):")
        assert info is not None
        assert info.country == "Montenegro"

    def test_multiword_country(self) -> None:
        info = parse_speaker_info("Mr. Cunningham (United States of America):")
        assert info is not None
        assert info.country == "United States of America"

    def test_benites_verson(self) -> None:
        info = parse_speaker_info("Mr. Benítez Versón (Cuba) (spoke in Spanish):")
        assert info is not None
        assert info.country == "Cuba"
        assert info.language == "Spanish"

    def test_he_title(self) -> None:
        info = parse_speaker_info("H.E. Mr. Smith (Australia):")
        assert info is not None
        assert info.country == "Australia"

    def test_returns_none_for_non_speaker(self) -> None:
        assert parse_speaker_info("Agenda item 13") is None
        assert parse_speaker_info("It was so decided.") is None


class TestSplitAttributionAndBody:
    def test_simple(self) -> None:
        attr, body = _split_attribution_and_body(
            "Mr. Smith (USA): Hello, this is the speech."
        )
        assert "Smith" in attr
        assert "Hello" in body

    def test_president(self) -> None:
        attr, body = _split_attribution_and_body(
            "The President: I call on the delegate."
        )
        assert "President" in attr
        assert "delegate" in body

    def test_no_body(self) -> None:
        attr, body = _split_attribution_and_body("Mr. Smith (USA):")
        assert "Smith" in attr
        assert body == ""
