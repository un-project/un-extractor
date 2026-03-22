"""Extract document-level metadata from the cover page section.

All extraction is rule-based (regex).  The cover page contains:
  - Document symbol (top-right running header): A/64/PV.121
  - Meeting ordinal: "121st plenary meeting"
  - Date: "Monday, 13 September 2010, 3 p.m."
  - Location: "New York" or "Geneva"
  - President line: "President: Mr. Name ……… (Country)"
"""

from __future__ import annotations

import re
from datetime import date
from typing import Literal

from src.models import PresidentInfo, TextBlock

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# e.g. A/64/PV.121  or  S/PV.9453
_SYMBOL_RE = re.compile(r"\b([AS]/(?:\d+/)?PV\.(\d+))\b")

# e.g. "121st plenary meeting" — also matches "10th PLENARY IEmNO" (OCR-garbled MEETING)
_MEETING_NUM_RE = re.compile(
    r"\b(\d+)(?:st|nd|rd|th)\s+plenary\s+meeting", re.IGNORECASE
)
# Looser fallback: requires only "Nth PLENARY" — handles OCR where MEETING is garbled
_MEETING_NUM_PLENARY_RE = re.compile(
    r"\b(\d+)(?:st|nd|rd|th)\s+plenary\b", re.IGNORECASE
)

# Date within cover text
_DATE_RE = re.compile(
    r"\b(\d{1,2})\s+"
    r"(January|February|March|April|May|June|July|August|"
    r"September|October|November|December)"
    r"\s+(\d{4})\b",
    re.IGNORECASE,
)
# OCR fallback: older scans render the digit "1" as capital "I"
# e.g. "I November 1993" instead of "1 November 1993"
_DATE_OCR_RE = re.compile(
    r"(?<!\w)I\s+"
    r"(January|February|March|April|May|June|July|August|"
    r"September|October|November|December)"
    r"\s+(\d{4})\b",
    re.IGNORECASE,
)

# Session from symbol: A/64/ → 64
_SESSION_FROM_SYMBOL_RE = re.compile(r"[AS]/(\d+)/PV\.")

# SC cover pages carry "Eighty-first year", "Seventy-third year", etc.
# The UN year count starts at 1 in 1946, matching GA session numbers exactly.
_SC_YEAR_RE = re.compile(
    r"\b(First|Second|Third|Fourth|Fifth|Sixth|Seventh|Eighth|Ninth|Tenth"
    r"|Eleventh|Twelfth|Thirteenth|Fourteenth|Fifteenth|Sixteenth|Seventeenth"
    r"|Eighteenth|Nineteenth|Twentieth"
    r"|Twenty[-\s]first|Twenty[-\s]second|Twenty[-\s]third|Twenty[-\s]fourth"
    r"|Twenty[-\s]fifth|Twenty[-\s]sixth|Twenty[-\s]seventh|Twenty[-\s]eighth"
    r"|Twenty[-\s]ninth|Thirtieth"
    r"|Thirty[-\s]first|Thirty[-\s]second|Thirty[-\s]third|Thirty[-\s]fourth"
    r"|Thirty[-\s]fifth|Thirty[-\s]sixth|Thirty[-\s]seventh|Thirty[-\s]eighth"
    r"|Thirty[-\s]ninth|Fortieth"
    r"|Forty[-\s]first|Forty[-\s]second|Forty[-\s]third|Forty[-\s]fourth"
    r"|Forty[-\s]fifth|Forty[-\s]sixth|Forty[-\s]seventh|Forty[-\s]eighth"
    r"|Forty[-\s]ninth|Fiftieth"
    r"|Fifty[-\s]first|Fifty[-\s]second|Fifty[-\s]third|Fifty[-\s]fourth"
    r"|Fifty[-\s]fifth|Fifty[-\s]sixth|Fifty[-\s]seventh|Fifty[-\s]eighth"
    r"|Fifty[-\s]ninth|Sixtieth"
    r"|Sixty[-\s]first|Sixty[-\s]second|Sixty[-\s]third|Sixty[-\s]fourth"
    r"|Sixty[-\s]fifth|Sixty[-\s]sixth|Sixty[-\s]seventh|Sixty[-\s]eighth"
    r"|Sixty[-\s]ninth|Seventieth"
    r"|Seventy[-\s]first|Seventy[-\s]second|Seventy[-\s]third|Seventy[-\s]fourth"
    r"|Seventy[-\s]fifth|Seventy[-\s]sixth|Seventy[-\s]seventh|Seventy[-\s]eighth"
    r"|Seventy[-\s]ninth|Eightieth"
    r"|Eighty[-\s]first|Eighty[-\s]second|Eighty[-\s]third|Eighty[-\s]fourth"
    r"|Eighty[-\s]fifth|Eighty[-\s]sixth|Eighty[-\s]seventh|Eighty[-\s]eighth"
    r"|Eighty[-\s]ninth|Ninetieth"
    r"|Ninety[-\s]first|Ninety[-\s]second|Ninety[-\s]third|Ninety[-\s]fourth"
    r"|Ninety[-\s]fifth|Ninety[-\s]sixth|Ninety[-\s]seventh|Ninety[-\s]eighth"
    r"|Ninety[-\s]ninth|One\s+hundredth"
    r")\s+year\b",
    re.IGNORECASE,
)

_SC_ORDINAL_MAP: dict[str, int] = {
    "first": 1, "second": 2, "third": 3, "fourth": 4, "fifth": 5,
    "sixth": 6, "seventh": 7, "eighth": 8, "ninth": 9, "tenth": 10,
    "eleventh": 11, "twelfth": 12, "thirteenth": 13, "fourteenth": 14,
    "fifteenth": 15, "sixteenth": 16, "seventeenth": 17, "eighteenth": 18,
    "nineteenth": 19, "twentieth": 20,
    "twentyfirst": 21, "twentysecond": 22, "twentythird": 23,
    "twentyfourth": 24, "twentyfifth": 25, "twentysixth": 26,
    "twentyseventh": 27, "twentyeighth": 28, "twentyninth": 29,
    "thirtieth": 30,
    "thirtyfirst": 31, "thirtysecond": 32, "thirtythird": 33,
    "thirtyfourth": 34, "thirtyfifth": 35, "thirtysixth": 36,
    "thirtyseventh": 37, "thirtyeighth": 38, "thirtyninth": 39,
    "fortieth": 40,
    "fortyfirst": 41, "fortysecond": 42, "fortythird": 43,
    "fortyfourth": 44, "fortyfifth": 45, "fortysixth": 46,
    "fortyseventh": 47, "fortyeighth": 48, "fortyninth": 49,
    "fiftieth": 50,
    "fiftyfirst": 51, "fiftysecond": 52, "fiftythird": 53,
    "fiftyfourth": 54, "fiftyfifth": 55, "fiftysixth": 56,
    "fiftyseventh": 57, "fiftyeighth": 58, "fiftyninth": 59,
    "sixtieth": 60,
    "sixtyfirst": 61, "sixtysecond": 62, "sixtythird": 63,
    "sixtyfourth": 64, "sixtyfifth": 65, "sixtysixth": 66,
    "sixtyseventh": 67, "sixtyeighth": 68, "sixtyninth": 69,
    "seventieth": 70,
    "seventyfirst": 71, "seventysecond": 72, "seventythird": 73,
    "seventyfourth": 74, "seventyfifth": 75, "seventysixth": 76,
    "seventyseventh": 77, "seventyeighth": 78, "seventyninth": 79,
    "eightieth": 80,
    "eightyfirst": 81, "eightysecond": 82, "eightythird": 83,
    "eightyfourth": 84, "eightyfifth": 85, "eightysixth": 86,
    "eightyseventh": 87, "eightyeighth": 88, "eightyninth": 89,
    "ninetieth": 90,
    "ninetyfirst": 91, "ninetysecond": 92, "ninetythird": 93,
    "ninetyfourth": 94, "ninetyfifth": 95, "ninetysixth": 96,
    "ninetyseventh": 97, "ninetyeighth": 98, "ninetyninth": 99,
    "onehundredth": 100,
}

# President line with dot-leaders: "President:  Mr. Name ……… (Country)"
# Handles both consecutive dots (GA: "...........") and spaced dots (SC: ". .  .  .")
_PRESIDENT_RE = re.compile(
    r"President\s*:\s*(.+?)\s*[.\s]{3,}\s*\(([^)]+)\)", re.DOTALL
)
# Fallback: older format without dot-leaders, e.g. "President: Mr. INSANALLY (Guyana)"
_PRESIDENT_SIMPLE_RE = re.compile(r"President\s*:\s*(.+?)\s*\(([^)]+)\)", re.DOTALL)

_MONTH_MAP: dict[str, int] = {
    "january": 1,
    "february": 2,
    "march": 3,
    "april": 4,
    "may": 5,
    "june": 6,
    "july": 7,
    "august": 8,
    "september": 9,
    "october": 10,
    "november": 11,
    "december": 12,
}


# ---------------------------------------------------------------------------
# Extraction functions (each accepts a plain string or list of TextBlocks)
# ---------------------------------------------------------------------------


def extract_symbol(text: str) -> str | None:
    """Return the document symbol (e.g. ``A/64/PV.121``) from *text*."""
    m = _SYMBOL_RE.search(text)
    return m.group(1) if m else None


def extract_session(symbol: str) -> int | None:
    """Return the session number from a document symbol (GA only)."""
    m = _SESSION_FROM_SYMBOL_RE.search(symbol)
    return int(m.group(1)) if m else None


def extract_sc_session(text: str) -> int | None:
    """Return the session/year number from SC cover text (e.g. 'Seventy-third year' → 73)."""
    m = _SC_YEAR_RE.search(text)
    if not m:
        return None
    # Normalise: lower-case, strip hyphens and spaces between components
    key = re.sub(r"[-\s]+", "", m.group(1).lower())
    return _SC_ORDINAL_MAP.get(key)


def extract_meeting_number(text: str, symbol: str | None = None) -> int | None:
    """Return the meeting number.

    Primary source: document symbol (e.g. ``A/64/PV.121`` → 121).
    Fallback 1: ordinal text "121st plenary meeting".
    Fallback 2: looser "121st PLENARY" (handles OCR-garbled MEETING word).
    """
    if symbol:
        m = re.search(r"PV\.(\d+)$", symbol)
        if m:
            return int(m.group(1))
    m = _MEETING_NUM_RE.search(text) or _MEETING_NUM_PLENARY_RE.search(text)
    return int(m.group(1)) if m else None


def extract_date(text: str) -> date | None:
    """Return meeting date parsed from *text*, or ``None``."""
    m = _DATE_RE.search(text)
    if m:
        day = int(m.group(1))
        month = _MONTH_MAP[m.group(2).lower()]
        year = int(m.group(3))
        if 1945 <= year <= 2100:
            return date(year, month, day)
    # OCR fallback: some older scans render "1" as capital "I",
    # e.g. "I November 1993" instead of "1 November 1993".
    m = _DATE_OCR_RE.search(text)
    if m:
        month = _MONTH_MAP[m.group(1).lower()]
        year = int(m.group(2))
        if 1945 <= year <= 2100:
            return date(year, month, 1)
    return None


def extract_location(text: str) -> str | None:
    """Return the meeting location from *text*."""
    upper = text.upper()
    if "NEW YORK" in upper:
        return "New York"
    if "GENEVA" in upper:
        return "Geneva"
    return None


def extract_president(text: str) -> PresidentInfo | None:
    """Return president name and country from *text*."""
    m = _PRESIDENT_RE.search(text) or _PRESIDENT_SIMPLE_RE.search(text)
    if not m:
        return None
    # Strip trailing dot-leaders, underscores, or spaces from the name.
    from src.pdf.clean_text import normalize_allcaps

    name = normalize_allcaps(re.sub(r"[\s._\-]+$", "", m.group(1).strip()))
    return PresidentInfo(name=name, country=m.group(2).strip())


def extract_body(symbol: str) -> Literal["GA", "SC"]:
    """Return ``"GA"`` or ``"SC"`` based on the document symbol."""
    if symbol.startswith("A/"):
        return "GA"
    return "SC"


def extract_all(blocks: list[TextBlock]) -> dict[str, object]:
    """Extract all metadata from the cover page blocks.

    Returns a dict with keys: symbol, session, meeting_number, date,
    location, president, body.  Missing values are ``None``.
    """
    full_text = " ".join(b.text for b in blocks)

    symbol = extract_symbol(full_text)
    if symbol and symbol.startswith("A/"):
        session = extract_session(symbol)
    else:
        session = extract_sc_session(full_text)
    meeting_number = extract_meeting_number(full_text, symbol)
    meeting_date = extract_date(full_text)
    location = extract_location(full_text)
    president = extract_president(full_text)
    body = extract_body(symbol) if symbol else "GA"

    return {
        "symbol": symbol,
        "session": session,
        "meeting_number": meeting_number,
        "date": meeting_date,
        "location": location,
        "president": president,
        "body": body,
    }
