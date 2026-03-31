"""Heuristic matching of representative names to ``speakers`` table rows.

The DHL representative CSVs store names in ``Last, First`` format with a
pipe-separated ``alternative_names`` field.  Speakers extracted from PDFs
are often stored as ``"Mr. LastName"`` or ``"Ms. LastName"`` in the DB.

``find_speaker_id`` tries a sequence of progressively broader candidates,
returning the first match.

Lookup order
------------
For each candidate name (primary + each alternative):
  1. Exact match: ``Speaker.name == display_name``
  2. Salutation + last word: e.g. ``"Mr. Smith"`` ilike ``"%Smith%"``
  3. Last-word substring: ``ilike "%Smith%"`` (current behaviour)
"""

from __future__ import annotations

import re

from sqlalchemy.orm import Session

from src.db.models import Speaker


def normalise_name(raw: str) -> str:
    """Convert ``"Last, First"`` → ``"First Last"``; strip birth years."""
    # Strip trailing birth/death year e.g. ", 1909-1974"
    raw = re.sub(r",\s*\d{4}(?:-\d{4})?$", "", raw).strip()
    if "," in raw:
        last, _, first = raw.partition(",")
        return f"{first.strip()} {last.strip()}"
    return raw.strip()


def _last_word(name: str) -> str:
    """Return the last whitespace-delimited token of *name* (uppercase)."""
    parts = name.split()
    return parts[-1].upper() if parts else ""


def _candidates(primary_raw: str, alt_raw: str, salutation: str | None) -> list[str]:
    """Return ordered list of (display_name, salutation_prefix) pairs to try.

    Each element is a ``(display_name, sal)`` tuple where ``sal`` is the
    salutation string (e.g. ``"Mr."``) or ``None``.
    """
    names_raw: list[str] = [primary_raw]
    if alt_raw:
        for a in alt_raw.split("|"):
            a = a.strip()
            if a:
                names_raw.append(a)

    seen: set[str] = set()
    result: list[tuple[str, str | None]] = []
    for raw in names_raw:
        display = normalise_name(raw)
        if display and display not in seen:
            seen.add(display)
            result.append((display, salutation))
    return result


def find_speaker_id(
    session: Session,
    primary_raw: str,
    alt_raw: str,
    salutation: str | None,
    country_id: int | None,
) -> int | None:
    """Return ``speakers.id`` for the best match, or ``None``.

    Parameters
    ----------
    session:
        Active SQLAlchemy session.
    primary_raw:
        Primary name from the CSV (may be ``"Last, First"`` format).
    alt_raw:
        Pipe-separated alternative names string (may be empty).
    salutation:
        ``"Mr."``, ``"Ms."``, ``"Dr."`` etc., or ``None``.
    country_id:
        ``countries.id``; only speakers for this country are searched.
        If ``None`` no match is attempted.
    """
    if not country_id:
        return None

    candidates = _candidates(primary_raw, alt_raw, salutation)
    if not candidates:
        return None

    for display, sal in candidates:
        last = _last_word(display)
        if not last or len(last) <= 1:
            continue

        # 1. Exact match
        spk = (
            session.query(Speaker)
            .filter_by(country_id=country_id)
            .filter(Speaker.name == display)
            .first()
        )
        if spk:
            return spk.id

        # 2. Salutation + last word  ("Mr. Smith")
        if sal:
            sal_clean = sal.rstrip(".")
            spk = (
                session.query(Speaker)
                .filter_by(country_id=country_id)
                .filter(Speaker.name.ilike(f"%{sal_clean}%{last}%"))
                .first()
            )
            if spk:
                return spk.id

        # 3. Last-word substring
        spk = (
            session.query(Speaker)
            .filter_by(country_id=country_id)
            .filter(Speaker.name.ilike(f"%{last}%"))
            .first()
        )
        if spk:
            return spk.id

    return None
