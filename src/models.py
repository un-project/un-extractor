"""Shared data models for the UN meeting extraction pipeline.

Internal representation:
  TextBlock -- paragraph-level unit produced by PDF extraction.

Output Pydantic models:
  DocumentItem  -- one agenda item or other named section in a meeting.
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


class SpeakerInfo(BaseModel):
    name: str
    country: str | None = None
    organization: str | None = None  # non-country affiliation (NGO, UN body, etc.)
    language: str | None = None  # spoken language; None means English
    role: str | None = None  # e.g. "Representative", "President"
    title: str | None = None  # e.g. "Mr.", "Mrs.", "Ms.", "H.E."
    on_behalf_of: str | None = None  # group represented


class Speech(BaseModel):
    position: int  # document-wide ordinal (stable ordering across items)
    position_in_item: int = 0  # order within its DocumentItem (shared counter with
    # stage_directions and resolutions for reconstruction)
    speaker: SpeakerInfo
    text: str


class StageDirection(BaseModel):
    position: int  # document-wide ordinal
    position_in_item: int = 0  # order within its DocumentItem
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
    position_in_item: int = 0  # order within its DocumentItem

    model_config = {"arbitrary_types_allowed": True}


class DocumentItem(BaseModel):
    """One agenda item or other named section within a meeting.

    The three element lists share a common ``position_in_item`` counter so the
    full document can be reconstructed by merging them ordered by that field.

    To reconstruct document order within an item::

        all_elements = (
            [("speech", s.position_in_item, s) for s in item.speeches]
            + [("stage_direction", d.position_in_item, d)
               for d in item.stage_directions]
            + [("resolution", r.position_in_item, r) for r in item.resolutions]
        )
        all_elements.sort(key=lambda x: x[1])
    """

    position: int  # order of this item in the meeting
    item_type: Literal["agenda_item", "other_item"]
    title: str
    agenda_number: int | None = None  # set for agenda_item type
    sub_item: str | None = None  # e.g. "b" for sub-item (b)
    continued: bool = False
    speeches: list[Speech] = []
    stage_directions: list[StageDirection] = []
    resolutions: list[Resolution] = []


class MeetingRecord(BaseModel):
    symbol: str  # e.g. "A/64/PV.121"
    body: Literal["GA", "SC"]
    session: int
    meeting_number: int
    date: date
    location: str
    president: PresidentInfo | None = None
    items: list[DocumentItem] = []

    @field_validator("symbol")
    @classmethod
    def validate_symbol(cls, v: str) -> str:
        if not re.match(r"[AS]/(?:\d+/)?PV\.\d+", v):
            raise ValueError(f"Invalid document symbol: {v!r}")
        return v
