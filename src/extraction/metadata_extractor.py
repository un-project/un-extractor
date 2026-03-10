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

# e.g. "121st plenary meeting"
_MEETING_NUM_RE = re.compile(
    r"\b(\d+)(?:st|nd|rd|th)\s+plenary\s+meeting", re.IGNORECASE
)

# Date within cover text
_DATE_RE = re.compile(
    r"\b(\d{1,2})\s+"
    r"(January|February|March|April|May|June|July|August|"
    r"September|October|November|December)"
    r"\s+(\d{4})\b",
    re.IGNORECASE,
)

# Session from symbol: A/64/ → 64
_SESSION_FROM_SYMBOL_RE = re.compile(r"[AS]/(\d+)/PV\.")

# President line with dot-leaders: "President:  Mr. Name ……… (Country)"
_PRESIDENT_RE = re.compile(r"President\s*:\s*(.+?)\s*\.{2,}\s*\(([^)]+)\)", re.DOTALL)
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
    """Return the session number from a document symbol."""
    m = _SESSION_FROM_SYMBOL_RE.search(symbol)
    return int(m.group(1)) if m else None


def extract_meeting_number(text: str, symbol: str | None = None) -> int | None:
    """Return the meeting number.

    Primary source: document symbol (e.g. ``A/64/PV.121`` → 121).
    Fallback: ordinal text in cover page (e.g. "121st plenary meeting").
    """
    if symbol:
        m = re.search(r"PV\.(\d+)$", symbol)
        if m:
            return int(m.group(1))
    m = _MEETING_NUM_RE.search(text)
    return int(m.group(1)) if m else None


def extract_date(text: str) -> date | None:
    """Return meeting date parsed from *text*, or ``None``."""
    m = _DATE_RE.search(text)
    if not m:
        return None
    day = int(m.group(1))
    month = _MONTH_MAP[m.group(2).lower()]
    year = int(m.group(3))
    return date(year, month, day)


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
    session = extract_session(symbol) if symbol else None
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
