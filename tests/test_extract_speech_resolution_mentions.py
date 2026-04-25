"""Unit tests for scripts/extract_speech_resolution_mentions.py."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.extract_speech_resolution_mentions import _extract_symbols, _lookup


# ---------------------------------------------------------------------------
# _extract_symbols
# ---------------------------------------------------------------------------


class TestExtractSymbols:
    def test_draft_symbol_explicit(self):
        syms = _extract_symbols("We co-sponsor draft resolution A/64/L.72.")
        assert "A/64/L.72" in syms

    def test_draft_symbol_committee(self):
        syms = _extract_symbols("See draft resolution A/C.3/78/L.5/Rev.1.")
        assert "A/C.3/78/L.5/REV.1" in syms

    def test_adopted_full_ga(self):
        syms = _extract_symbols("Refer to resolution A/RES/64/299.")
        assert "A/RES/64/299" in syms

    def test_adopted_full_sc(self):
        syms = _extract_symbols("Acting under S/RES/1441.")
        assert "S/RES/1441" in syms

    def test_adopted_full_sc_with_year(self):
        # The regex captures S/RES/1441 (word boundary before the parenthetical)
        syms = _extract_symbols("Pursuant to S/RES/1441(2002).")
        assert "S/RES/1441" in syms

    def test_natural_language_ga(self):
        syms = _extract_symbols("Resolution 64/299 was adopted.")
        assert "64/299" in syms

    def test_natural_language_sc(self):
        syms = _extract_symbols("Acting under resolution 1441.")
        assert "S/RES/1441" in syms

    def test_natural_language_sc_with_year(self):
        syms = _extract_symbols("Pursuant to resolution 1441 (2002).")
        assert "S/RES/1441" in syms

    def test_sc_number_below_threshold_ignored(self):
        # Very low numbers like "resolution 5" are not SC resolution numbers
        syms = _extract_symbols("Resolution 5 was discussed.")
        assert "S/RES/5" not in syms

    def test_multiple_symbols_in_one_speech(self):
        text = (
            "Draft resolution A/64/L.72 and draft resolution A/64/L.73 "
            "both refer to resolution 63/100."
        )
        syms = _extract_symbols(text)
        assert "A/64/L.72" in syms
        assert "A/64/L.73" in syms
        assert "63/100" in syms

    def test_deduplication(self):
        text = "Resolution 64/299 was discussed. Resolution 64/299 was adopted."
        syms = _extract_symbols(text)
        assert isinstance(syms, set)
        assert "64/299" in syms

    def test_no_symbols_in_plain_text(self):
        text = "The meeting was called to order at 3 p.m."
        assert _extract_symbols(text) == set()

    def test_normalization_uppercase(self):
        syms = _extract_symbols("See draft resolution a/64/l.72.")
        assert "A/64/L.72" in syms

    def test_trailing_punctuation_stripped(self):
        syms = _extract_symbols("draft resolution A/64/L.72,")
        assert "A/64/L.72" in syms
        assert "A/64/L.72," not in syms


# ---------------------------------------------------------------------------
# _lookup
# ---------------------------------------------------------------------------


class TestLookup:
    """_lookup tests against a synthetic symbol index."""

    def _idx(self) -> dict[str, int]:
        return {
            "A/64/L.72": 1,
            "64/299": 2,
            "A/RES/64/299": 2,
            "S/RES/1441": 3,
            "S/RES/1441(2002)": 3,
        }

    def test_exact_draft(self):
        assert _lookup("A/64/L.72", self._idx()) == 1

    def test_exact_adopted_ga_short(self):
        assert _lookup("64/299", self._idx()) == 2

    def test_exact_adopted_ga_full(self):
        assert _lookup("A/RES/64/299", self._idx()) == 2

    def test_ga_short_to_full_expansion(self):
        # "64/299" not in index directly, but "A/RES/64/299" is
        idx = {"A/RES/64/299": 2}
        assert _lookup("64/299", idx) == 2

    def test_ga_full_to_short_expansion(self):
        # "A/RES/64/299" not in index, but "64/299" is
        idx = {"64/299": 2}
        assert _lookup("A/RES/64/299", idx) == 2

    def test_sc_year_stripped(self):
        # "S/RES/1441(2002)" → look up as "S/RES/1441"
        idx = {"S/RES/1441": 3}
        assert _lookup("S/RES/1441(2002)", idx) == 3

    def test_missing_returns_none(self):
        assert _lookup("A/99/L.99", self._idx()) is None

    def test_case_insensitive(self):
        assert _lookup("a/64/l.72", self._idx()) == 1
