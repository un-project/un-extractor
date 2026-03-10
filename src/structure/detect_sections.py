"""Segment a flat stream of TextBlocks into typed document sections.

A UN verbatim record contains interleaved:
  - Cover page (first page, distinct layout)
  - Agenda item headers (bold, "Agenda item N …")
  - Speaker turns (bold name attribution followed by speech paragraphs)
  - Stage directions (italic text: adoptions, procedural decisions …)
  - Draft resolution headers (bold "Draft resolution (A/…)")

This module classifies each ``TextBlock`` and groups consecutive blocks
into ``Section`` objects that downstream extractors can work with.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from src.models import TextBlock

# ---------------------------------------------------------------------------
# Section types
# ---------------------------------------------------------------------------

SectionType = Literal[
    "cover",
    "agenda_item",
    "speaker_turn",
    "stage_direction",
    "resolution_header",
    "body",
]


@dataclass
class Section:
    """A logical document section consisting of one or more TextBlocks."""

    section_type: SectionType
    blocks: list[TextBlock] = field(default_factory=list)
    # Position counter (0-based) relative to the full document block stream.
    position: int = 0

    @property
    def text(self) -> str:
        return " ".join(b.text.strip() for b in self.blocks if b.text.strip())


# ---------------------------------------------------------------------------
# Regex patterns for section boundary detection
# ---------------------------------------------------------------------------

# Speaker attribution: "Mr. Smith (Country):" or "The President:"
# Allows optional language note and handles multi-word names / H.E. titles.
_SPEAKER_RE = re.compile(
    r"^(?:H\.E\.\s+)?(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+\S.{0,60}?\s*\([^)]+\)\s*"
    r"(?:\([^)]+\)\s*)?:",
    re.IGNORECASE,
)

# Titular speakers without country (President, Secretary-General, etc.)
_TITULAR_RE = re.compile(
    r"^The\s+(?:President|Secretary-General|Chair(?:man|woman|person)?|"
    r"Deputy\s+Secretary-General|Acting\s+President)\b",
    re.IGNORECASE,
)

# Secretariat / department speaker: "Ms. Sharma (Department for …):"
_DEPT_SPEAKER_RE = re.compile(
    r"^(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s+\S.{0,60}?\s*\((?:Department|Office|Division|"
    r"Bureau|Secretariat)[^)]*\)\s*:",
    re.IGNORECASE,
)

# Agenda item: "Agenda item 13" or "Agenda items 21 to 26"
_AGENDA_RE = re.compile(r"^Agenda\s+items?\s+\d+", re.IGNORECASE)

# Draft resolution / decision header
_DRAFT_RE = re.compile(
    r"^Draft\s+(?:resolution|decision)\s+\(?(A/\S+|S/\S+)", re.IGNORECASE
)

# Adoption italic line: "Draft resolution X was adopted …"
_ADOPTION_RE = re.compile(
    r"Draft\s+(?:resolution|decision)\s+\S+.*was\s+adopted", re.IGNORECASE
)

# Suspension / resumption
_SUSPENSION_RE = re.compile(r"meeting\s+was\s+suspended", re.IGNORECASE)
_RESUMPTION_RE = re.compile(r"meeting\s+(?:was\s+)?resumed", re.IGNORECASE)
_ADJOURNMENT_RE = re.compile(r"meeting\s+rose", re.IGNORECASE)
_SILENCE_RE = re.compile(r"minute\s+of\s+silence", re.IGNORECASE)
_LANGUAGE_NOTE_RE = re.compile(r"^\(spoke\s+in\s+\w+\)\s*$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Block classification helpers
# ---------------------------------------------------------------------------


def _is_speaker_block(block: TextBlock) -> bool:
    """True if *block* is the opening attribution of a speech."""
    if not block.bold_start:
        return False
    text = block.text.strip()
    return bool(
        _SPEAKER_RE.match(text)
        or _TITULAR_RE.match(text)
        or _DEPT_SPEAKER_RE.match(text)
    )


def _is_agenda_block(block: TextBlock) -> bool:
    return block.bold_start and bool(_AGENDA_RE.match(block.text.strip()))


def _is_draft_resolution_block(block: TextBlock) -> bool:
    return block.bold_start and bool(_DRAFT_RE.match(block.text.strip()))


def _stage_direction_type(
    text: str,
) -> Literal[
    "adoption",
    "decision",
    "suspension",
    "resumption",
    "adjournment",
    "silence",
    "language_note",
    "other",
]:
    if _ADOPTION_RE.search(text):
        return "adoption"
    if "It was so decided" in text or "decision" in text.lower():
        return "decision"
    if _SUSPENSION_RE.search(text):
        return "suspension"
    if _RESUMPTION_RE.search(text):
        return "resumption"
    if _ADJOURNMENT_RE.search(text):
        return "adjournment"
    if _SILENCE_RE.search(text):
        return "silence"
    if _LANGUAGE_NOTE_RE.match(text.strip()):
        return "language_note"
    return "other"


# ---------------------------------------------------------------------------
# Main segmentation
# ---------------------------------------------------------------------------

# Cover page ends when we see the first real agenda item or speaker turn.
_COVER_PAGE_LIMIT = 1  # First page (index 0) is always the cover.


def detect_sections(blocks: list[TextBlock]) -> list[Section]:
    """Segment *blocks* into typed ``Section`` objects.

    The first page is emitted as a single ``cover`` section.
    Subsequent blocks are classified and accumulated into sections that
    end whenever a new section boundary is encountered.

    Parameters
    ----------
    blocks:
        Flat, ordered list of ``TextBlock`` objects (already cleaned).

    Returns
    -------
    list[Section]
        Ordered list of sections.
    """
    if not blocks:
        return []

    sections: list[Section] = []
    position: int = 0

    # ---- Cover section: everything on page 0 ----
    cover = Section(section_type="cover", position=position)
    for block in blocks:
        if block.page_num == 0:
            cover.blocks.append(block)
    if cover.blocks:
        sections.append(cover)
        position += 1

    # ---- Body: pages 1+ ----
    current: Section | None = None

    for block in blocks:
        if block.page_num == 0:
            continue  # already handled

        if block.all_italic:
            # Stage direction: flush current section, emit standalone direction.
            if current is not None:
                sections.append(current)
                current = None
            sd = Section(
                section_type="stage_direction",
                blocks=[block],
                position=position,
            )
            sections.append(sd)
            position += 1
            continue

        if _is_agenda_block(block):
            if current is not None:
                sections.append(current)
            current = Section(
                section_type="agenda_item",
                blocks=[block],
                position=position,
            )
            position += 1
            continue

        if _is_draft_resolution_block(block):
            if current is not None:
                sections.append(current)
            current = Section(
                section_type="resolution_header",
                blocks=[block],
                position=position,
            )
            position += 1
            continue

        if _is_speaker_block(block):
            if current is not None:
                sections.append(current)
            current = Section(
                section_type="speaker_turn",
                blocks=[block],
                position=position,
            )
            position += 1
            continue

        # Continuation: append to current section (or start a body section).
        if current is None:
            current = Section(
                section_type="body",
                blocks=[block],
                position=position,
            )
            position += 1
        else:
            current.blocks.append(block)

    if current is not None:
        sections.append(current)

    return sections
