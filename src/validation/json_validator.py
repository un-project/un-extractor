"""JSON schema validation for extracted meeting records.

Validates a ``MeetingRecord`` against the expected schema and returns
a list of validation errors.  An empty list means the record is valid.

On failure the pipeline can retry extraction or flag the document for
manual review.
"""

from __future__ import annotations

import re
from datetime import date

from src.models import MeetingRecord, Resolution, Speech, StageDirection

# ---------------------------------------------------------------------------
# Validation error container
# ---------------------------------------------------------------------------


class ValidationError:
    """One failed validation check."""

    def __init__(self, field: str, message: str) -> None:
        self.field = field
        self.message = message

    def __repr__(self) -> str:
        return f"ValidationError({self.field!r}: {self.message!r})"

    def __str__(self) -> str:
        return f"{self.field}: {self.message}"


# ---------------------------------------------------------------------------
# Field-level checks
# ---------------------------------------------------------------------------

_SYMBOL_RE = re.compile(r"^[AS]/(?:\d+/)?PV\.\d+$")
_DRAFT_SYMBOL_RE = re.compile(r"^(?:A|S)/\S+/L\.\d+")
_ADOPTED_SYMBOL_RE = re.compile(r"^\d+/\d+$")


def _check_symbol(symbol: str | None) -> list[ValidationError]:
    if not symbol:
        return [ValidationError("symbol", "missing")]
    if not _SYMBOL_RE.match(symbol):
        return [ValidationError("symbol", f"invalid format: {symbol!r}")]
    return []


def _check_date(d: date | None) -> list[ValidationError]:
    if d is None:
        return [ValidationError("date", "missing")]
    if d.year < 1945 or d.year > 2100:
        return [ValidationError("date", f"year out of range: {d.year}")]
    return []


def _check_session(session: int | None) -> list[ValidationError]:
    if session is None:
        return [ValidationError("session", "missing")]
    if session <= 0:
        return [ValidationError("session", f"must be positive, got {session}")]
    return []


def _check_meeting_number(meeting_number: int | None) -> list[ValidationError]:
    if meeting_number is None:
        return [ValidationError("meeting_number", "missing")]
    if meeting_number <= 0:
        return [
            ValidationError("meeting_number", f"must be positive, got {meeting_number}")
        ]
    return []


def _check_resolution(res: Resolution, idx: int) -> list[ValidationError]:
    errors: list[ValidationError] = []
    prefix = f"resolutions[{idx}]"

    if not res.draft_symbol:
        errors.append(ValidationError(f"{prefix}.draft_symbol", "missing"))
    elif not _DRAFT_SYMBOL_RE.match(res.draft_symbol):
        errors.append(
            ValidationError(
                f"{prefix}.draft_symbol",
                f"unexpected format: {res.draft_symbol!r}",
            )
        )

    if res.vote_type == "recorded":
        if res.yes_count is None:
            errors.append(
                ValidationError(f"{prefix}.yes_count", "required for recorded vote")
            )
        if res.no_count is None:
            errors.append(
                ValidationError(f"{prefix}.no_count", "required for recorded vote")
            )
        if res.abstain_count is None:
            errors.append(
                ValidationError(f"{prefix}.abstain_count", "required for recorded vote")
            )
        for i, cv in enumerate(res.country_votes):
            if not cv.country:
                errors.append(
                    ValidationError(f"{prefix}.country_votes[{i}].country", "missing")
                )

    return errors


def _check_speech(speech: Speech, idx: int) -> list[ValidationError]:
    errors: list[ValidationError] = []
    prefix = f"speeches[{idx}]"
    if not speech.speaker.name:
        errors.append(ValidationError(f"{prefix}.speaker.name", "missing"))
    if not speech.text:
        errors.append(ValidationError(f"{prefix}.text", "empty"))
    return errors


def _check_stage_direction(sd: StageDirection, idx: int) -> list[ValidationError]:
    errors: list[ValidationError] = []
    if not sd.text:
        errors.append(ValidationError(f"stage_directions[{idx}].text", "empty"))
    return errors


# ---------------------------------------------------------------------------
# Top-level validator
# ---------------------------------------------------------------------------


def validate_record(record: MeetingRecord) -> list[ValidationError]:
    """Return a list of ``ValidationError`` for *record*.

    An empty list means the record passed all checks.
    """
    errors: list[ValidationError] = []

    errors.extend(_check_symbol(record.symbol))
    errors.extend(_check_date(record.date))
    errors.extend(_check_session(record.session))
    errors.extend(_check_meeting_number(record.meeting_number))

    if not record.location:
        errors.append(ValidationError("location", "missing"))

    for i, res in enumerate(record.resolutions):
        errors.extend(_check_resolution(res, i))

    for i, speech in enumerate(record.speeches):
        errors.extend(_check_speech(speech, i))

    for i, sd in enumerate(record.stage_directions):
        errors.extend(_check_stage_direction(sd, i))

    return errors


def is_valid(record: MeetingRecord) -> bool:
    """Return ``True`` if *record* passes all validation checks."""
    return len(validate_record(record)) == 0
