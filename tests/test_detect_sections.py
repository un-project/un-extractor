"""Tests for section detection and agenda header parsing."""

from __future__ import annotations

import pytest

from src.pipeline.process_pdf import _parse_agenda_header
from src.structure.detect_sections import _is_agenda_block, _is_speaker_block
from src.models import FormattedSegment, TextBlock

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bold_block(text: str) -> TextBlock:
    return TextBlock(
        segments=[FormattedSegment(text=text, bold=True, italic=False)],
        page_num=0,
        y0=100.0,
        x0=50.0,
    )


def _plain_block(text: str) -> TextBlock:
    """Non-bold, non-italic block — simulates scanned docs with no font metadata."""
    return TextBlock(
        segments=[FormattedSegment(text=text, bold=False, italic=False)],
        page_num=1,
        y0=100.0,
        x0=50.0,
    )


# ---------------------------------------------------------------------------
# _is_agenda_block — detection
# ---------------------------------------------------------------------------


class TestIsAgendaBlock:
    @pytest.mark.parametrize(
        "text",
        [
            "Agenda item 13",
            "Agenda items 21 to 26",
            "Agenda item 13 (continued)",
            "Agenda items 21 to 26 (continued)",
        ],
    )
    def test_standard_forms_detected(self, text: str) -> None:
        assert _is_agenda_block(_bold_block(text))

    @pytest.mark.parametrize(
        "text",
        [
            "AGENDA ITEM 13",
            "AGENDA ITEMS 21 TO 26",
            "AGENDA ITEM 13 (CONTINUED)",
        ],
    )
    def test_allcaps_scanned_forms_detected(self, text: str) -> None:
        # Scanned/OCR docs: ALL-CAPS headings without bold metadata
        block = TextBlock(
            segments=[FormattedSegment(text=text, bold=False, italic=False)],
            page_num=0,
            y0=100.0,
            x0=50.0,
        )
        assert _is_agenda_block(block)

    def test_non_agenda_not_detected(self) -> None:
        assert not _is_agenda_block(_bold_block("Mr. Smith (France):"))
        assert not _is_agenda_block(_bold_block("Draft resolution (A/64/L.1)"))


# ---------------------------------------------------------------------------
# _is_speaker_block — ALL-CAPS attribution patterns (pre-1985 documents)
# ---------------------------------------------------------------------------


class TestIsSpeakerBlockAllCaps:
    """Pre-1985 UN documents print speaker attributions in ALL CAPS, e.g.:
    ``MR. MOLOTOV (Union of Soviet Socialist Republics):``
    These blocks have no bold/italic metadata, so the detection relies on the
    ALL-CAPS title pattern.
    """

    @pytest.mark.parametrize(
        "text",
        [
            "MR. MOLOTOV (Union of Soviet Socialist Republics):",
            "MRS. PANDIT (India):",
            "MS. JONES (Country):",
            "DR. EVATT (Australia):",
            "PROF. KRISHNA MENON (India):",
            "MR. MALIK (USSR): Speech text starts here",
            "MRS. PANDIT (India) (spoke in French):",
            # semicolon OCR error for colon
            "MR. MOLOTOV (USSR);",
        ],
    )
    def test_allcaps_title_no_paragraph_number(self, text: str) -> None:
        assert _is_speaker_block(_plain_block(text))

    @pytest.mark.parametrize(
        "text",
        [
            "THE PRESIDENT:",
            "THE SECRETARY-GENERAL:",
            "THE CHAIRMAN:",
        ],
    )
    def test_allcaps_titular_detected(self, text: str) -> None:
        assert _is_speaker_block(_plain_block(text))

    @pytest.mark.parametrize(
        "text",
        [
            "Some general body text without attribution.",
            "The delegation of France wishes to state…",
            "In favour: Algeria, Angola, Argentina",
            "AGENDA ITEM 9",
        ],
    )
    def test_non_speaker_not_detected(self, text: str) -> None:
        assert not _is_speaker_block(_plain_block(text))


# ---------------------------------------------------------------------------
# _parse_agenda_header — parsing
# ---------------------------------------------------------------------------


class TestParseAgendaHeader:
    def test_simple(self) -> None:
        num, sub, cont, title = _parse_agenda_header(
            "Agenda item 13 Prevention of conflict"
        )
        assert num == 13
        assert sub is None
        assert cont is False
        assert title == "Prevention of conflict"

    def test_continued_inline(self) -> None:
        num, sub, cont, title = _parse_agenda_header("Agenda item 13 (continued)")
        assert num == 13
        assert cont is True
        assert sub is None

    def test_continued_with_title(self) -> None:
        num, sub, cont, title = _parse_agenda_header(
            "Agenda item 13 (continued) Prevention of conflict",
        )
        assert num == 13
        assert cont is True
        assert title == "Prevention of conflict"

    def test_continued_with_sub_item(self) -> None:
        num, sub, cont, title = _parse_agenda_header(
            "Agenda item 13 (continued)\n(b) Sub-item title"
        )
        assert num == 13
        assert cont is True
        assert sub == "b"
        assert title == "Sub-item title"

    def test_range(self) -> None:
        num, sub, cont, title = _parse_agenda_header(
            "Agenda items 21 to 26 (continued)"
        )
        assert num == 21
        assert cont is True

    def test_allcaps_continued(self) -> None:
        num, sub, cont, title = _parse_agenda_header("AGENDA ITEM 9 (CONTINUED)")
        assert num == 9
        assert cont is True
