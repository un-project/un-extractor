"""Unit tests for src/pdf/clean_text.py — noise filtering and inline stripping."""

from __future__ import annotations

import pytest

from src.pdf.clean_text import _DOC_CODE_RE, _strip_inline_noise, repair_hyphenation


class TestDocCodeRe:
    """_DOC_CODE_RE must match all doc-code / page-number block variants."""

    @pytest.mark.parametrize(
        "text",
        [
            # Plain codes
            "22-58466",
            "10-53066 (E)",
            # Code + bare *jobnum*
            "24-25633 (E) *2425633*",
            # Code + page number
            "07-50429 2",
            "07-50429 14",
            # Code + page fraction
            "17-29573 21/25",
            # Page fraction + code (space separator)
            "22/25 17-29573",
            "4/22 24-40822",
            # Page fraction + code (\x08 separator — newer PDFs)
            "2/9\x08 24-25633",
            # Code + \x08 + page fraction
            "24-25633\x08 3/9",
            # Bare starred job number
            "*1070469*",
        ],
    )
    def test_matches_noise(self, text: str) -> None:
        assert _DOC_CODE_RE.match(text.strip()), f"should match: {text!r}"

    @pytest.mark.parametrize(
        "text",
        [
            "New York",
            "24-25633 is a document symbol",
            "The resolution was adopted",
        ],
    )
    def test_does_not_match_content(self, text: str) -> None:
        assert not _DOC_CODE_RE.match(text.strip()), f"should not match: {text!r}"


class TestStripInlineNoise:
    """_strip_inline_noise must remove inline doc-code runs from block text."""

    def test_starred_jobnum_suffix(self) -> None:
        text = "to hear\n\n24-25633 (E) *2425633*\n\nthe remaining speakers"
        result = _strip_inline_noise(text)
        assert "24-25633" not in result
        assert "to hear" in result
        assert "the remaining speakers" in result

    def test_backspace_page_then_code(self) -> None:
        text = "from 1945 to this\n\n2/9\x08 24-25633\n\ndate, more than 2,000"
        result = _strip_inline_noise(text)
        assert "24-25633" not in result
        assert "\x08" not in result
        assert "from 1945 to this" in result
        assert "date, more than 2,000" in result

    def test_backspace_code_then_page(self) -> None:
        text = "although it has\n\n24-25633\x08 3/9\n\nnot yet come into force"
        result = _strip_inline_noise(text)
        assert "24-25633" not in result
        assert "\x08" not in result
        assert "although it has" in result
        assert "not yet come into force" in result

    def test_plain_inline_code(self) -> None:
        # Original case: no backspace, no starred jobnum
        text = "first sentence\n\n07-50429 14\n\nsecond sentence"
        result = _strip_inline_noise(text)
        assert "07-50429" not in result
        assert "first sentence" in result
        assert "second sentence" in result


# ---------------------------------------------------------------------------
# repair_hyphenation
# ---------------------------------------------------------------------------


class TestRepairHyphenation:
    """repair_hyphenation must join OCR soft-hyphen artifacts from pre-1990 docs."""

    @pytest.mark.parametrize(
        "broken, fixed",
        [
            # Standard within-block OCR artifacts (hyphen + space + lowercase)
            ("codifica- tion", "codification"),
            ("disarma- ment", "disarmament"),
            ("establish- ment", "establishment"),
            ("Organiza- tion", "Organization"),
            ("satisfac- tory", "satisfactory"),
            ("neces- sary", "necessary"),
            ("unequi- vocal", "unequivocal"),
            # Multi-word context — repair is applied in-situ
            (
                "political codifica- tion of the rules",
                "political codification of the rules",
            ),
            (
                "nuclear disarma- ment will prove",
                "nuclear disarmament will prove",
            ),
            # Proper nouns
            ("Seychel- les", "Seychelles"),
            ("Domini- can Republic", "Dominican Republic"),
            # Across-block / cross-paragraph (hyphen + newline + lowercase)
            ("Declara-\n\ntion on the Establis", "Declaration on the Establis"),
            ("recom-\nmendation", "recommendation"),
        ],
    )
    def test_soft_hyphen_joined(self, broken: str, fixed: str) -> None:
        assert repair_hyphenation(broken) == fixed

    @pytest.mark.parametrize(
        "text",
        [
            # Hyphen + uppercase continuation → intentional compound, leave intact
            "Secretary- General",
            "non-proliferation",  # no space → hard hyphen, untouched
            "well-known",  # no space → hard hyphen, untouched
            "The meeting rose at 5 p.m.",  # no hyphen at all
        ],
    )
    def test_hard_hyphen_unchanged(self, text: str) -> None:
        assert repair_hyphenation(text) == text

    def test_idempotent(self) -> None:
        """Applying the function twice produces the same result."""
        text = "codifica- tion of disarma- ment measures"
        once = repair_hyphenation(text)
        twice = repair_hyphenation(once)
        assert once == twice

    def test_empty_string(self) -> None:
        assert repair_hyphenation("") == ""
