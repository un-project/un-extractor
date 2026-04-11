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

    # -----------------------------------------------------------------------
    # ALL-CAPS title patterns (pre-1985 documents)
    # -----------------------------------------------------------------------

    def test_allcaps_mr(self) -> None:
        info = parse_speaker_info("MR. MOLOTOV (USSR):")
        assert info is not None
        assert "Molotov" in info.name

    def test_allcaps_mrs_with_language(self) -> None:
        info = parse_speaker_info("MRS. PANDIT (India) (spoke in French):")
        assert info is not None
        assert "Pandit" in info.name
        assert info.country == "India"
        assert info.language == "French"

    def test_allcaps_dr(self) -> None:
        info = parse_speaker_info("DR. EVATT (Australia):")
        assert info is not None
        assert info.country == "Australia"

    def test_allcaps_the_president(self) -> None:
        info = parse_speaker_info("THE PRESIDENT:")
        assert info is not None
        assert info.country is None
        assert "President" in info.name

    def test_allcaps_title_normalised_to_mixed_case(self) -> None:
        info = parse_speaker_info("MR. MALIK (Pakistan):")
        assert info is not None
        # normalize_allcaps should convert MALIK → Malik
        assert "Malik" in info.name


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

    def test_allcaps_attribution_no_number(self) -> None:
        attr, body = _split_attribution_and_body(
            "MR. MOLOTOV (USSR): The delegation of the Soviet Union…"
        )
        assert "MOLOTOV" in attr
        assert "Soviet" in body

    def test_allcaps_titular_no_number(self) -> None:
        attr, body = _split_attribution_and_body(
            "THE PRESIDENT: The meeting is called to order."
        )
        assert "PRESIDENT" in attr
        assert "meeting" in body

    def test_scanned_with_paragraph_number_allcaps_title(self) -> None:
        # Older scanned docs: paragraph number + ALL-CAPS title + CAPS surname
        attr, body = _split_attribution_and_body(
            "1. MR. AHMED (Pakistan): I should like to join…"
        )
        # Paragraph number stripped; attribution covers title + name + country
        assert "AHMED" in attr
        assert "join" in body
