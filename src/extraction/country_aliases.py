"""Country name normalization for UN documents.

Applies a static lookup table of known OCR typos, abbreviated forms, and
informal names before any LLM normalization step.  All corrections map raw
strings (as they appear in extracted PDF text) to their official UN Member
State names.

The lookup is case-insensitive so it catches capitalization variants too.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Static alias table
# ---------------------------------------------------------------------------
# Keys are raw strings as they may appear in extracted text.
# Values are the official UN Member State names.
# Keep entries grouped by category for easy maintenance.

_ALIASES: dict[str, str] = {
    # ------------------------------------------------------------------
    # OCR typos
    # ------------------------------------------------------------------
    "Austalia": "Australia",
    "Austrlia": "Australia",
    "Australa": "Australia",
    "Austraia": "Australia",
    "Asutralia": "Australia",
    "Australlia": "Australia",
    "Australaia": "Australia",
    "Columbia": "Colombia",         # common OCR/spelling error
    # ------------------------------------------------------------------
    # "The X" / article prefix variants
    # ------------------------------------------------------------------
    "The Bahamas": "Bahamas",
    "the Bahamas": "Bahamas",
    "The Gambia": "Gambia",
    "the Gambia": "Gambia",
    "The Netherlands": "Netherlands",
    "the Netherlands": "Netherlands",
    "The Philippines": "Philippines",
    "the Philippines": "Philippines",
    "The Solomon Islands": "Solomon Islands",
    "the Solomon Islands": "Solomon Islands",
    # ------------------------------------------------------------------
    # "Republic of X" variants present in older PV records
    # ------------------------------------------------------------------
    "Republic of Azerbaijan": "Azerbaijan",
    "Republic of Belarus": "Belarus",
    "Republic of Benin": "Benin",
    "Republic of Croatia": "Croatia",
    "Republic of Moldova": "Moldova",
    "Republic of North Macedonia": "North Macedonia",
    "Republic of San Marino": "San Marino",
    "Republic of Seychelles": "Seychelles",
    "Republic of the Congo": "Congo",
    # ------------------------------------------------------------------
    # "State of X" variants
    # ------------------------------------------------------------------
    "State of Qatar": "Qatar",
    # ------------------------------------------------------------------
    # "X (Formal form of)" / parenthetical variants
    # ------------------------------------------------------------------
    "Bolivia (Plurinational State of)": "Plurinational State of Bolivia",
    "Iran (Islamic Republic of)": "Islamic Republic of Iran",
    "Venezuela (Bolivarian Republic of)": "Bolivarian Republic of Venezuela",
    # ------------------------------------------------------------------
    # Short / informal forms of long official names
    # ------------------------------------------------------------------
    "United States": "United States of America",
    "United Kingdom": "United Kingdom of Great Britain and Northern Ireland",
    "Great Britain": "United Kingdom of Great Britain and Northern Ireland",
    "Britain": "United Kingdom of Great Britain and Northern Ireland",
    "Russia": "Russian Federation",
    "Iran": "Islamic Republic of Iran",
    "Syria": "Syrian Arab Republic",
    "Tanzania": "United Republic of Tanzania",
    "Korea": "Republic of Korea",
    "South Korea": "Republic of Korea",
    "North Korea": "Democratic People's Republic of Korea",
    "Vietnam": "Viet Nam",
    "Viet-Nam": "Viet Nam",
    "Laos": "Lao People's Democratic Republic",
    "Bolivia": "Plurinational State of Bolivia",
    "Venezuela": "Bolivarian Republic of Venezuela",
    "Ivory Coast": "Côte d'Ivoire",
    "Cote d'Ivoire": "Côte d'Ivoire",
    "Côte dIvoire": "Côte d'Ivoire",
    "Democratic Republic of Congo": "Democratic Republic of the Congo",
    "DR Congo": "Democratic Republic of the Congo",
    "DRC": "Democratic Republic of the Congo",
    "Macedonia": "North Macedonia",
    "Burma": "Myanmar",
    "Palestine": "State of Palestine",
    "Czech Republic": "Czechia",
    "Swaziland": "Eswatini",
    "Micronesia": "Micronesia (Federated States of)",
    "Federated States of Micronesia": "Micronesia (Federated States of)",
    "Saint Kitts": "Saint Kitts and Nevis",
    "Saint Vincent": "Saint Vincent and the Grenadines",
    "Trinidad": "Trinidad and Tobago",
    "Antigua": "Antigua and Barbuda",
    "Bosnia": "Bosnia and Herzegovina",
    "East Timor": "Timor-Leste",
    "Brunei": "Brunei Darussalam",
    "Cape Verde": "Cabo Verde",
    "Turkey": "Türkiye",
    # ------------------------------------------------------------------
    # "Arab/Islamic/Grand/Commonwealth/Slovak Republic of X" variants
    # ------------------------------------------------------------------
    "Arab Republic of Egypt": "Egypt",
    "Commonwealth of Dominica": "Dominica",
    "Grand Duchy of Luxembourg": "Luxembourg",
    "Islamic Republic of Pakistan": "Pakistan",
    "Kyrgyz Republic": "Kyrgyzstan",
    "Slovak Republic": "Slovakia",
    # ------------------------------------------------------------------
    # Encoding / diacritic variants for the same official name
    # ------------------------------------------------------------------
    "Sao Tomé and Principe": "Sao Tome and Principe",
    "São Tomé and Príncipe": "Sao Tome and Principe",
    "São Tomé and Principe": "Sao Tome and Principe",
    "Sao Tomé and Príncipe": "Sao Tome and Principe",
    "São Tomé": "Sao Tome and Principe",
    "Sao Tomé": "Sao Tome and Principe",
    "São Tome": "Sao Tome and Principe",
    # ------------------------------------------------------------------
    # Abbreviations
    # ------------------------------------------------------------------
    "USA": "United States of America",
    "US": "United States of America",
    "UK": "United Kingdom of Great Britain and Northern Ireland",
    "UAE": "United Arab Emirates",
    "ROK": "Republic of Korea",
    "DPRK": "Democratic People's Republic of Korea",
    # ------------------------------------------------------------------
    # Older/former official names still found in older PV records
    # ------------------------------------------------------------------
    "Yugoslav Republic of Macedonia": "North Macedonia",
    "Former Yugoslav Republic of Macedonia": "North Macedonia",
    "The former Yugoslav Republic of Macedonia": "North Macedonia",
    "Libyan Arab Jamahiriya": "Libya",
    "Byelorussian SSR": "Belarus",
    "Byelorussia": "Belarus",
    "Belorussia": "Belarus",
    "Ukrainian SSR": "Ukraine",
    "Zaire": "Democratic Republic of the Congo",
}

# Build a lowercase lookup for case-insensitive matching
_ALIASES_LOWER: dict[str, str] = {k.lower(): v for k, v in _ALIASES.items()}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def normalize_country_name(name: str) -> str:
    """Return the canonical UN Member State name for *name*.

    If *name* matches a known alias or typo (case-insensitively), the
    canonical name is returned.  Otherwise *name* is returned unchanged.
    """
    stripped = name.strip()
    canonical = _ALIASES_LOWER.get(stripped.lower())
    return canonical if canonical is not None else stripped
