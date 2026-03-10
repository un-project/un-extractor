"""Shared data models for the UN meeting extraction pipeline.

Internal representation:
  TextBlock -- paragraph-level unit produced by PDF extraction.

Output Pydantic models:
  MeetingRecord -- top-level JSON output for one meeting.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date  # noqa: F401 – used in Pydantic annotations at runtime
from typing import Literal

from pydantic import BaseModel, field_validator

# ---------------------------------------------------------------------------
# Internal representation (dataclasses – not serialised to JSON)
# ---------------------------------------------------------------------------


@dataclass
class FormattedSegment:
    """A run of text with homogeneous bold/italic formatting."""

    text: str
    bold: bool
    italic: bool


@dataclass
class TextBlock:
    """A paragraph-level text unit produced by PDF extraction.

    Corresponds roughly to one PyMuPDF block, but guaranteed to be in
    two-column reading order and free of header/footer noise.
    """

    segments: list[FormattedSegment]
    page_num: int
    y0: float
    x0: float

    @property
    def text(self) -> str:
        return "".join(s.text for s in self.segments)

    @property
    def bold_start(self) -> bool:
        """True if the first non-whitespace segment is bold."""
        for seg in self.segments:
            if seg.text.strip():
                return seg.bold
        return False

    @property
    def all_italic(self) -> bool:
        """True if every non-whitespace segment is italic."""
        meaningful = [s for s in self.segments if s.text.strip()]
        return bool(meaningful) and all(s.italic for s in meaningful)

    @property
    def has_bold(self) -> bool:
        return any(s.bold for s in self.segments if s.text.strip())


# ---------------------------------------------------------------------------
# Output Pydantic models (serialised to JSON)
# ---------------------------------------------------------------------------


class PresidentInfo(BaseModel):
    name: str
    country: str | None = None


class AgendaItem(BaseModel):
    number: int
    sub_item: str | None = None
    title: str
    continued: bool = False


class SpeakerInfo(BaseModel):
    name: str
    country: str | None = None
    language: str | None = None  # spoken language; None means English
    role: str | None = None  # e.g. "Representative", "President"
    title: str | None = None  # e.g. "Mr.", "Mrs.", "Ms.", "H.E."
    on_behalf_of: str | None = None  # group represented


class Speech(BaseModel):
    position: int
    speaker: SpeakerInfo
    text: str


class StageDirection(BaseModel):
    position: int
    text: str
    direction_type: Literal[
        "adoption",
        "decision",
        "suspension",
        "resumption",
        "adjournment",
        "silence",
        "language_note",
        "other",
    ] = "other"


class CountryVote(BaseModel):
    country: str
    vote_position: Literal["yes", "no", "abstain"]


class Resolution(BaseModel):
    draft_symbol: str
    adopted_symbol: str | None = None
    title: str | None = None
    vote_type: Literal["consensus", "recorded"] = "consensus"
    yes_count: int | None = None
    no_count: int | None = None
    abstain_count: int | None = None
    country_votes: list[CountryVote] = []

    model_config = {"arbitrary_types_allowed": True}


class MeetingRecord(BaseModel):
    symbol: str  # e.g. "A/64/PV.121"
    body: Literal["GA", "SC"]
    session: int
    meeting_number: int
    date: date
    location: str
    president: PresidentInfo | None = None
    agenda_items: list[AgendaItem] = []
    speeches: list[Speech] = []
    stage_directions: list[StageDirection] = []
    resolutions: list[Resolution] = []

    @field_validator("symbol")
    @classmethod
    def validate_symbol(cls, v: str) -> str:
        if not re.match(r"[AS]/(?:\d+/)?PV\.\d+", v):
            raise ValueError(f"Invalid document symbol: {v!r}")
        return v
