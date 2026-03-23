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

_UK = "United Kingdom of Great Britain and Northern Ireland"

_ALIASES: dict[str, str] = {
    # ------------------------------------------------------------------
    # OCR typos — United Arab Emirates
    # ------------------------------------------------------------------
    "United Arab EInirates": "United Arab Emirates",
    "United Arab Fmirates": "United Arab Emirates",
    "United Arab Rnirates": "United Arab Emirates",
    "United Arab anirates": "United Arab Emirates",
    "United Arab gmirates": "United Arab Emirates",
    "United. Arab Emirates": "United Arab Emirates",
    "United Arab": "United Arab Emirates",
    "Jnitcd Arab Emirates": "United Arab Emirates",  # "(J…" after leading-punct strip
    "united Arab &nirates": "United Arab Emirates",
    "united Arab ZWirates": "United Arab Emirates",
    # ------------------------------------------------------------------
    # OCR typos — United Kingdom
    # ------------------------------------------------------------------
    "United Kmgdom": _UK,
    "United Kingdom of Great Britain": _UK,
    "United Kingdom of Great Britain and Northern": _UK,
    "United Kingdan of Great Britain and Northern Ireland": _UK,
    "United Kingdom cif Great Britain and Northern Ireland": _UK,
    "United Kingdom of Great Britain and Nortnern Ireland": _UK,
    "United Kingdom of Great Britain and l'brthern Ireland": _UK,
    "United Kingdom of Great Britain and'Northern Ireland": _UK,
    "United Kingdom of Grea~ Britain and Northern rrelanrl": _UK,
    "United Kingdom of Gr.eat Britain and Northern Ireland": _UK,
    "United ~ingdom of Great Britain and Northern Ireland": _UK,
    "United ~ingdom of Great Britain and Northe~n Ireland": _UK,
    "United Kingdom of Great Britain a~d Northern Ireland": _UK,
    "United Kingdan of Great Britain 2Ild Northern Ireland": _UK,
    "united. Kingdom of Great Britain and Northern Ireland": _UK,
    # ------------------------------------------------------------------
    # OCR typos — United States of America
    # ------------------------------------------------------------------
    "United Sta tes of Mer i ca": "United States of America",
    "United States of Amenca": "United States of America",
    "United States of Amer ica": "United States of America",
    "United States of Amer- ica": "United States of America",
    "United Sta~es of America": "United States of America",
    "UnitedStates of America": "United States of America",
    "United States ofAmerica": "United States of America",
    "United States of' America": "United States of America",
    "United States of'America": "United States of America",
    "united Sta tes of 1Imer ica": "United States of America",
    "United Sta tes of 1Imer ica": "United States of America",
    "Unit": "United States of America",  # severely truncated (iso3=USA in DHL data)
    "United States of Amerit:a": "United States of America",  # OCR : for i
    "United States of American": "United States of America",  # trailing n
    "the United States of America": "United States of America",  # leading "the"
    # ------------------------------------------------------------------
    # OCR typos — United Republic of Tanzania
    # ------------------------------------------------------------------
    "United Bepublic of Tanzania": "United Republic of Tanzania",
    "United Republic cf Tanzania": "United Republic of Tanzania",
    "United Republic.of Tanzania": "United Republic of Tanzania",
    "United Repub'4.~ of Tan~ania": "United Republic of Tanzania",
    "United Republic of Tanli!ania": "United Republic of Tanzania",
    # ------------------------------------------------------------------
    # OCR typos — United Republic of Cameroon
    # ------------------------------------------------------------------
    "United Republic of CamerQOn": "United Republic of Cameroon",
    # ------------------------------------------------------------------
    # OCR typos — other
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
    "Liechenstein": "Liechtenstein",  # different transposition
    "Liechstenstein": "Liechtenstein",  # extra s
    "Guinea Bissau": "Guinea-Bissau",
    "Guinea- Bissau": "Guinea-Bissau",  # space before dash
    "United Arab Emirate": "United Arab Emirates",  # truncated trailing s
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
    "Democratic People's": "Democratic People's Republic of Korea",  # truncated
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
    "Côte": "Côte d'Ivoire",  # severely truncated form
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
    # OCR typos that caused iso3 squatting (blocker rows for canonical rows)
    # ------------------------------------------------------------------
    # "Arab Republic" stole iso3='EGY' — merge into Egypt
    "Arab Republic": "Egypt",
    # "Northern Ireland" stole iso3='GBR' — merge into UK
    "Northern Ireland": "United Kingdom of Great Britain and Northern Ireland",
    # "Tobago" stole iso3='TTO' — merge into Trinidad and Tobago
    "Tobago": "Trinidad and Tobago",
    # DHL comma-inverted form for West Germany
    "Germany, Federal Republic Of": "Germany",
    "Germany, Federal Republic of": "Germany",
    # "German DemOcratic Republic" (OCR caps) stole iso3='DDR' — merge into correct form
    "German DemOcratic Republic": "German Democratic Republic",
    # Truncated names that grabbed iso3 codes
    "German Democratic": "German Democratic Republic",  # truncated
    "Trinidad and": "Trinidad and Tobago",  # truncated
    # ------------------------------------------------------------------
    # OCR space-in-hyphen variants
    # ------------------------------------------------------------------
    "Timor- Leste": "Timor-Leste",
    "Timor -Leste": "Timor-Leste",
    # ------------------------------------------------------------------
    # Netherlands parenthetical / comma-inverted forms
    # ------------------------------------------------------------------
    "Netherlands (Kingdom of the Netherlands)": "Netherlands",
    "Netherlands, Kingdom of the": "Netherlands",
    # ------------------------------------------------------------------
    # Federal Republic of Germany (West Germany, UN member 1973–1990)
    # ------------------------------------------------------------------
    "Federal Republic of Germany": "Germany",
    # ------------------------------------------------------------------
    # Côte d'Ivoire — curly/right-single-quote apostrophe variant
    # ------------------------------------------------------------------
    "Côte d\u2019Ivoire": "Côte d'Ivoire",
    # ------------------------------------------------------------------
    # Saint Kitts and Nevis — French name used in older UN records
    # ------------------------------------------------------------------
    "Saint Christophe-et-Niévès": "Saint Kitts and Nevis",
    "Saint Christophe-et-Nieves": "Saint Kitts and Nevis",
    "Saint Christophe": "Saint Kitts and Nevis",
    # ------------------------------------------------------------------
    # Uruguay — formal/inverted forms
    # ------------------------------------------------------------------
    "Oriental Republic of Uruguay": "Uruguay",
    "Eastern Republic of Uruguay": "Uruguay",
    "Uruguay, Eastern Republic of": "Uruguay",
    # ------------------------------------------------------------------
    # Venezuela — DHL comma-inverted form
    # ------------------------------------------------------------------
    "Venezuela, Bolivarian Republic of": "Bolivarian Republic of Venezuela",
    # ------------------------------------------------------------------
    # Historical UN member states / spelling variants
    # ------------------------------------------------------------------
    "Democratic Kampuchea": "Cambodia",  # 1975–1989
    "Kampuchea": "Cambodia",
    "Kazakstan": "Kazakhstan",  # old UN spelling (1992–1995)
    "Ukrainian Soviet Socialist Republic": "Ukraine",
    # DHL CSV garbled / severely truncated forms
    "samoa": "Samoa",  # lowercase; _CANONICAL_NAMES doesn't cover it
    "vanuatu": "Vanuatu",  # lowercase; same
    "E Gambia": "Gambia",  # OCR artifact prefix
    "Gamb": "Gambia",  # severely truncated
    "United": "United States of America",  # severely truncated (iso3=USA in DHL data)
    # "Union of SOviet SOcialist Republics" (OCR caps) stole iso3='SUN'
    "Union of SOviet SOcialist Republics": "Union of Soviet Socialist Republics",
    # "Observer State of Palestine" stole iso3='PSE' from "State of Palestine"
    "Observer State of Palestine": "State of Palestine",
    "Observer for Palestine": "State of Palestine",
    # ------------------------------------------------------------------
    # OCR typos — additional United States of America variants
    # ------------------------------------------------------------------
    "Jnited States of America": "United States of America",  # J→U OCR glyph swap
    "Uni ted Sta tes of America": "United States of America",
    "Uni ted States of America": "United States of America",
    "Untted States of America": "United States of America",
    # ------------------------------------------------------------------
    # Older/former official names still found in older PV records
    # ------------------------------------------------------------------
    "Yugoslav Republic of Macedonia": "North Macedonia",
    "Former Yugoslav Republic of Macedonia": "North Macedonia",
    "The former Yugoslav Republic of Macedonia": "North Macedonia",
    "Socialist Republic of Viet Nam": "Viet Nam",
    "Libyan Arab Jamahiriya": "Libya",
    "Byelorussian SSR": "Belarus",
    "Byelorussia": "Belarus",
    "Belorussia": "Belarus",
    "Ukrainian SSR": "Ukraine",
    "Zaire": "Democratic Republic of the Congo",
}

# Build a lowercase lookup for case-insensitive matching
_ALIASES_LOWER: dict[str, str] = {k.lower(): v for k, v in _ALIASES.items()}

# Build a lowercase lookup for canonical-name case normalization.
# Allows "united states of america" → "United States of America" even though
# the canonical form is not itself an alias key.
_CANONICAL_NAMES: dict[str, str] = {v.lower(): v for v in _ALIASES.values()}

# ---------------------------------------------------------------------------
# Pre-processing regexes applied before alias lookup
# ---------------------------------------------------------------------------

# Strips embedded document/page-reference artifacts that OCR produces when a
# margin page number is interleaved with the vote-table text.  These always
# contain a backspace control character (\x08) flanked by digit sequences.
# Examples:
#   "United Arab 14-70313\x08 11/24 Emirates"  →  "United Arab Emirates"
#   "16/21\x08 22-71684 United Arab Emirates"  →  "United Arab Emirates"
#   "Czech 11-64365\x08 7 Republic"            →  "Czech Republic"
_DOC_REF_RE = re.compile(r"\s*\d[\d\-/]*\x08[\s\d/\-]+")

# Strips trailing procedural/vote text that OCR appended to a country name.
# Examples:
#   "… Northern Ireland The PRESIDENT: Draft resolution…"
#   "… Northern Ireland. The Acting President: …"
#   "United States of America (Mr. Guney"
#   "… Northern Ireland Draft reeolution II …"
_TRAILING_PROC_RE = re.compile(
    r"(?:"
    # "The President", "The Acting President", "The PRESIDENT", "The Assembly"
    r"\s+[^A-Za-z]*The\s+(?:Acting\s+)?(?:PRESIDENT|President|Assembly)\b.*"
    # "The third preambular paragraph…", "The following operative paragraph…", etc.
    # Enumerate specific ordinal/procedure adjectives to avoid false positives
    # (e.g. IGNORECASE would make [a-z]+ also match "Congo", "Republic", etc.)
    r"|\s+The\s+(?:first|second|third|fourth|fifth|sixth|seventh|eighth|ninth|tenth"
    r"|operative|preambular|following|aforementioned|last|next|above|whole|revised"
    r"|amendment|annex|same)\s+\w+\b.*"
    r"|\s+Draft\s+re\w{0,3}olution\b.*"
    r"|\s+A\s+[Rr]ecorded\s+vote\b.*"
    r"|\s+\(Mr\.\s.*"
    r"|\s+Operative\s+paragraph\b.*"
    r"|\s+May\s+I\s+take\s+it\b.*"
    r"|\s+I\s+now\s+(?:put|invite)\b.*"
    r"|\s+(?:Ab[a-z]?t|Against:|Aga\s+inst:).*"
    # "with N abstentions / votes / …"
    r"|\s+with\s+\d+\b.*" r")$",
    re.IGNORECASE | re.DOTALL,
)


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

    Applies several cleaning steps before the alias lookup:

    1. Strip embedded document-reference artifacts (backspace-delimited page
       numbers that OCR interleaves with country names).
    2. Normalize internal whitespace.
    3. Strip leading punctuation noise (leading dots, quotes, spaces).
    4. Strip trailing procedural/vote text appended by OCR.
    5. Alias lookup (case-insensitive).
    6. Case-normalize already-canonical names (e.g. "united states of america"
       → "United States of America").
    """
    stripped = name.strip()
    if not stripped:
        return stripped

    # 1. Remove \x08-based document-reference artifacts
    cleaned = _DOC_REF_RE.sub(" ", stripped)
    # 2. Normalize whitespace
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    # 3. Strip leading punctuation noise
    cleaned = re.sub(r'^[.\'"\s]+', "", cleaned)
    # 4. Strip trailing procedure / vote text
    cleaned = _TRAILING_PROC_RE.sub("", cleaned).rstrip(".,; ")

    # 4a. Title-case uniformly-cased names (DHL CSVs emit ALL-CAPS or all-lower).
    #     ALL-CAPS:  "ZANZIBAR" → "Zanzibar"
    #     all-lower: "oman"     → "Oman"
    #     Abbreviations (USA, UAE) still resolve via the case-insensitive
    #     alias lookup in step 5.
    if cleaned.isupper() or cleaned.islower():
        cleaned = cleaned.title()

    # 5. Alias lookup
    canonical = _ALIASES_LOWER.get(cleaned.lower())
    if canonical is not None:
        return canonical

    # 6. Case-normalize already-canonical names
    canonical_case = _CANONICAL_NAMES.get(cleaned.lower())
    if canonical_case is not None:
        return canonical_case

    return cleaned
