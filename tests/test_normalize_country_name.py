"""Parametrised tests for src/extraction/country_aliases.normalize_country_name.

The alias table (``_ALIASES``) is imported directly so that every entry is
automatically covered.  Adding or removing an alias entry immediately changes
the test count and surfaces regressions without any manual test maintenance.

Test groups
-----------
TestAliasTable       — every _ALIASES key maps to its declared canonical value
TestPreprocessing    — preprocessing steps (hyphen-space, ALL-CAPS, \x08 artifacts,
                       leading punctuation, trailing procedural text)
TestEdgeCases        — empty input, canonical names returned unchanged, case-
                       insensitive lookup of already-canonical names
"""

from __future__ import annotations

import pytest

from src.extraction.country_aliases import (
    _ALIASES,
    normalize_country_name,
)

# ---------------------------------------------------------------------------
# 1. Full alias table — parametrised
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("alias,expected", list(_ALIASES.items()))
def test_alias_resolves_to_canonical(alias: str, expected: str) -> None:
    """Every key in _ALIASES must resolve to its declared canonical value."""
    assert normalize_country_name(alias) == expected


# ---------------------------------------------------------------------------
# 2. Preprocessing pipeline
# ---------------------------------------------------------------------------


class TestPreprocessing:
    def test_hyphen_space_collapse(self) -> None:
        """OCR line-break artefact 'Ar- gentina' → 'Argentina'."""
        assert normalize_country_name("Ar- gentina") == "Argentina"

    def test_hyphen_space_collapse_multiword(self) -> None:
        """'United King- dom' → 'United Kingdom of Great Britain and Northern Ireland'."""
        assert normalize_country_name("United King- dom") == (
            "United Kingdom of Great Britain and Northern Ireland"
        )

    def test_all_caps_title_cased_then_resolved(self) -> None:
        """ALL-CAPS alias keys (e.g. 'USSR') are resolved via case-insensitive lookup."""
        assert normalize_country_name("USSR") == "Union of Soviet Socialist Republics"

    def test_all_caps_non_alias_title_cased(self) -> None:
        """ALL-CAPS non-alias name is title-cased and returned as-is."""
        assert normalize_country_name("FRANCE") == "France"

    def test_all_lower_non_alias_title_cased(self) -> None:
        """all-lowercase non-alias name is title-cased and returned as-is."""
        assert normalize_country_name("germany") == "Germany"

    def test_doc_ref_artifact_removed(self) -> None:
        """Embedded \x08-delimited page-number artefacts are stripped."""
        assert (
            normalize_country_name("United Arab 14-70313\x08 11/24 Emirates")
            == "United Arab Emirates"
        )

    def test_leading_punctuation_stripped(self) -> None:
        """Leading dots and quotes are removed before lookup."""
        assert normalize_country_name("'France") == "France"
        assert normalize_country_name(".France") == "France"

    def test_trailing_procedural_text_stripped(self) -> None:
        """Procedural text appended by OCR is stripped before lookup."""
        assert (
            normalize_country_name("France The PRESIDENT: Draft resolution A/64/L.1")
            == "France"
        )

    def test_trailing_draft_resolution_stripped(self) -> None:
        assert (
            normalize_country_name("Germany Draft resolution A/64/L.1 was adopted")
            == "Germany"
        )

    def test_internal_whitespace_normalised(self) -> None:
        """Multiple spaces are collapsed to one."""
        assert normalize_country_name("United  States  of  America") == (
            "United States of America"
        )


# ---------------------------------------------------------------------------
# 3. Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_string_returns_empty(self) -> None:
        assert normalize_country_name("") == ""

    def test_whitespace_only_returns_empty(self) -> None:
        assert normalize_country_name("   ") == ""

    def test_canonical_name_returned_unchanged(self) -> None:
        """Names that are already canonical should pass through unmodified."""
        assert normalize_country_name("France") == "France"
        assert normalize_country_name("Germany") == "Germany"
        assert normalize_country_name("Japan") == "Japan"

    def test_canonical_alias_target_case_normalised(self) -> None:
        """A canonical name in wrong case is corrected via _CANONICAL_NAMES lookup."""
        assert normalize_country_name("united states of america") == (
            "United States of America"
        )
        assert normalize_country_name("RUSSIAN FEDERATION") == "Russian Federation"

    def test_case_insensitive_alias_lookup(self) -> None:
        """Alias lookup is case-insensitive: 'russia' resolves the same as 'Russia'."""
        assert normalize_country_name("russia") == "Russian Federation"
        assert normalize_country_name("RUSSIA") == "Russian Federation"
