"""Country name normalization for UN documents.

Applies a static lookup table of known OCR typos, abbreviated forms, and
informal names before any LLM normalization step.  All corrections map raw
strings (as they appear in extracted PDF text) to their official UN Member
State names.

The lookup is case-insensitive so it catches capitalization variants too.
"""

from __future__ import annotations

import re

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
    "Columbia": "Colombia",  # common OCR/spelling error
    "Demark": "Denmark",
    "Irag": "Iraq",
    "Marshal Islands": "Marshall Islands",
    "United Arab Emiraes": "United Arab Emirates",
    "Mozambigue": "Mozambique",
    "Lichtenstein": "Liechtenstein",
    "Guinea Bissau": "Guinea-Bissau",
    # ------------------------------------------------------------------
    # "The X" / article prefix variants
    # ------------------------------------------------------------------
    "The Bahamas": "Bahamas",
    "the Bahamas": "Bahamas",
    "The Gambia": "Gambia",
    "the Gambia": "Gambia",
    "The Netherlands": "Netherlands",
    "the Netherlands": "Netherlands",
    "Kingdom of the Netherlands": "Netherlands",
    "The Philippines": "Philippines",
    "the Philippines": "Philippines",
    "The Solomon Islands": "Solomon Islands",
    "the Solomon Islands": "Solomon Islands",
    "Solomon": "Solomon Islands",
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
    # curly apostrophe variants
    "Democratic People\u2019s Republic of Korea": (
        "Democratic People's Republic of Korea"
    ),
    "Vietnam": "Viet Nam",
    "Viet-Nam": "Viet Nam",
    "Laos": "Lao People's Democratic Republic",
    # curly apostrophe variant
    "Lao People\u2019s Democratic Republic": "Lao People's Democratic Republic",
    "Bolivia": "Plurinational State of Bolivia",
    "Venezuela": "Bolivarian Republic of Venezuela",
    "Ivory Coast": "Côte d'Ivoire",
    "Cote d'Ivoire": "Côte d'Ivoire",
    "Côte dIvoire": "Côte d'Ivoire",
    "Cote d'lvoire": "Côte d'Ivoire",  # OCR: lowercase l for I
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
    "Saint Vincent and": "Saint Vincent and the Grenadines",
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
# Organization detection
# ---------------------------------------------------------------------------

# Words that, when found as whole words, reliably indicate an organization
# rather than a country name.  "federation" is intentionally excluded because
# "Russian Federation" is a valid country name.
_ORG_KEYWORDS: frozenset[str] = frozenset(
    {
        "organization",
        "organisation",
        "committee",
        "commission",
        "union",
        "fund",
        "agency",
        "programme",
        "program",
        "association",
        "council",
        "forum",
        "community",
        "institute",
        "institution",
        "bank",
        "court",
        "tribunal",
        "network",
        "coalition",
        "alliance",
        "congress",
        "conference",
        "initiative",
        "foundation",
        "society",
        "centre",
        "center",
        "league",
        "group",
        "authority",
        "system",
        "corporation",
        "company",
        "partnership",
        "project",
        "holdings",
        "limited",
    }
)

# Role-title prefixes: if the affiliation string starts with one of these
# (case-insensitive) it describes a person's role, not a country.
_ORG_ROLE_PREFIXES: tuple[str, ...] = (
    "president of",
    "president,",
    "secretary-general",
    "secretary of",
    "secretary,",
    "under-secretary",
    "assistant secretary",
    "executive director",
    "executive secretary",
    "director of",
    "director general",
    "director,",
    "chief,",
    "chief of",
    "chairman of",
    "chairperson",
    "chair,",
    "acting chairman",
    "acting chair",
    "acting secretary",
    "co-chair",
    "rapporteur",
    "special representative",
    "special adviser",
    "special advisor",
    "special envoy",
    "high commissioner",
    "deputy secretary",
    "deputy high",
    "judge,",
    "advocate of",
    "observer for",
    "united nations",  # catches all UN bodies
)

# Well-known acronyms / short names that don't contain any of the keywords
# above but are definitely not countries.
_ORG_ACRONYMS: frozenset[str] = frozenset(
    {
        "unicef",
        "unesco",
        "undp",
        "unfpa",
        "unhcr",
        "unep",
        "who",
        "fao",
        "imf",
        "wto",
        "ilo",
        "iaea",
        "icc",
        "icj",
        "icrc",
        "wmo",
        "icao",
        "imo",
        "itu",
        "upu",
        "wipo",
        "ifad",
        "unido",
        "interpol",
        "un-women",
        "gnp+",
        "access now",
        "social watch",
        "mena-rosa",
        "m17m.org",
        "south centre",
        "sovereign order of malta",
        "sovereign military order of malta",
    }
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_organization(name: str) -> bool:
    """Return ``True`` if *name* is an organization / role rather than a country.

    Call this *after* ``normalize_country_name`` so that known aliases have
    already been resolved (e.g. "Republic of the Congo" → "Congo").
    """
    lower = name.strip().lower()
    if not lower:
        return False
    # Known acronyms and explicit names
    if lower in _ORG_ACRONYMS:
        return True
    # Role-title prefixes
    for prefix in _ORG_ROLE_PREFIXES:
        if lower.startswith(prefix):
            return True
    # Organizational keywords as whole words
    for kw in _ORG_KEYWORDS:
        if re.search(r"\b" + re.escape(kw) + r"\b", lower):
            return True
    # Domain-style names (e.g. "M17M.ORG")
    if re.search(r"\.\w{2,4}$", lower):
        return True
    return False


def normalize_country_name(name: str) -> str:
    """Return the canonical UN Member State name for *name*.

    If *name* matches a known alias or typo (case-insensitively), the
    canonical name is returned.  Otherwise *name* is returned unchanged.
    """
    stripped = name.strip()
    canonical = _ALIASES_LOWER.get(stripped.lower())
    return canonical if canonical is not None else stripped
