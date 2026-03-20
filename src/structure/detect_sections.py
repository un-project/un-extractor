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

# ---------------------------------------------------------------------------
# Scanned / OCR-document fallback patterns (no bold/italic metadata preserved)
# ---------------------------------------------------------------------------

# Older verbatim records typeset speaker surnames in ALL CAPS and embed the
# attribution inline with the paragraph number, e.g.:
#   "1. Mr. AHMED (Pakistan):"
#   "56. Mr. ANDERSEN (Denmark):"
#   "106. Sir Maori KIKI (Papua New Guinea):"
# The separator is sometimes ";" due to OCR misreading ":".
_SCANNED_SPEAKER_RE = re.compile(
    r"^\d+\.\s+"
    r"(?:"
    r"(?:H\.E\.\s+)?(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+"  # standard title
    r"|(?:Sir|Dame)\s+\w+\s+"  # "Sir FirstName" or "Dame FirstName"
    r")"
    r"[A-Z]{2}[A-Z\w\-\s\.]*?"  # ALL-CAPS surname (≥ 2 consecutive caps)
    r"\s*\([^)]+\)"  # (Country or affiliation)
    r"(?:\s*\([^)]+\))?"  # optional second parenthetical
    r"\s*[:;]",
    re.UNICODE,
)

# Titular speakers that may or may not carry a paragraph number in scanned docs
_SCANNED_TITULAR_RE = re.compile(
    r"^(?:\d+\.\s+)?"
    r"The\s+(?:President|Secretary-General|Chair(?:man|woman|person)?|"
    r"Deputy\s+Secretary-General|Acting\s+President)"
    r"(?:\s*\([^)]+\))?"
    r"\s*[:;]",
    re.IGNORECASE,
)

# ALL-CAPS agenda heading used in older documents: "AGENDA ITEM 9"
_AGENDA_ALLCAPS_RE = re.compile(r"^AGENDA\s+ITEMS?\s+\d+", re.UNICODE)

# Draft resolution / decision header
_DRAFT_RE = re.compile(
    r"^Draft\s+(?:resolution|decision)\s+\(?(A/\S+|S/\S+)", re.IGNORECASE
)

# Adoption italic line — matches multiple formats:
#   "Draft resolution A/64/L.72 was adopted …"
#   "Draft resolution I was adopted …"   (Roman numeral)
#   "The amendment (A/65/L.53) was adopted …"
#   "The draft resolution was adopted …"
#   "Draft resolution was adopted by …"  (recent format: no symbol in line)
_ADOPTION_RE = re.compile(
    r"(?:Draft\s+(?:resolution|decision)\s+\S+.*was\s+adopted"
    r"|The\s+amendment\s+\([^)]+\)\s+was\s+adopted"
    r"|The\s+draft\s+(?:resolution|decision)\s+was\s+adopted"
    r"|Draft\s+(?:resolution|decision)\s+was\s+adopted)",
    re.IGNORECASE,
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
    text = block.text.strip()
    if block.bold_start:
        return bool(
            _SPEAKER_RE.match(text)
            or _TITULAR_RE.match(text)
            or _DEPT_SPEAKER_RE.match(text)
        )
    # Fallback for scanned/OCR documents where bold metadata is absent:
    # detect by ALL-CAPS surname pattern or titled speaker with paragraph number.
    return bool(_SCANNED_SPEAKER_RE.match(text) or _SCANNED_TITULAR_RE.match(text))


def _is_agenda_block(block: TextBlock) -> bool:
    text = block.text.strip()
    if block.bold_start:
        return bool(_AGENDA_RE.match(text))
    # Scanned docs typeset agenda headings in ALL CAPS without bold metadata.
    return bool(_AGENDA_ALLCAPS_RE.match(text))


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
    if "It was so decided" in text or re.search(
        r"draft\s+decision\s+was\s+adopted|The\s+decision\s+was\s+adopted",
        text,
        re.IGNORECASE,
    ):
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


def _is_content_boundary(block: TextBlock) -> bool:
    """Return True if this page-0 block marks the end of cover metadata.

    The cover metadata contains the meeting title line and president line.
    Italic blocks (stage directions like "The meeting was called to order")
    and all content blocks (speaker turns, agenda items, headings) are
    treated as content boundaries so they are processed by the main loop.
    """
    if _is_speaker_block(block):
        return True
    if _is_agenda_block(block):
        return True
    if _is_draft_resolution_block(block):
        return True
    # Italic text on the cover page (e.g. "The meeting was called to order")
    # should be emitted as a stage_direction, not buried in the cover section.
    # Exception: SC cover pages use italic for the President and Members roster.
    if block.all_italic or (
        block.italic_start and bool(_ADOPTION_RE.search(block.text.strip()))
    ):
        text = block.text.strip()
        if re.match(r"(?:President|Members)\s*:", text, re.IGNORECASE):
            return False  # cover metadata even if italic (SC cover page)
        return True
    # Bold heading that doesn't match any known metadata pattern
    if block.bold_start:
        text = block.text.strip()
        if (
            len(text) > 10
            # GA: "121st plenary meeting"; SC: "8422nd meeting"
            and not re.search(r"\d+\w*\s+(?:plenary\s+)?meeting", text, re.IGNORECASE)
            and not re.match(r"President\s*:", text, re.IGNORECASE)
            and not re.match(r"Official\s+Records", text, re.IGNORECASE)
            and not re.match(r"The\s+meeting\s+was", text, re.IGNORECASE)
            and not re.match(r"United\s+Nations", text, re.IGNORECASE)
            and not re.match(r"Security\s+Council", text, re.IGNORECASE)
        ):
            return True
    return False


def detect_sections(blocks: list[TextBlock]) -> list[Section]:
    """Segment *blocks* into typed ``Section`` objects.

    The cover section contains only the metadata blocks at the top of page 0
    (meeting title, president line, etc.).  Content that follows on page 0
    (speaker turns, agenda items, named headings) is processed as normal body
    sections — ensuring speeches and items from the first page are captured.

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

    # ---- Cover section: page-0 blocks up to the first content boundary ----
    cover = Section(section_type="cover", position=position)
    cover_end_idx: int = 0
    for i, block in enumerate(blocks):
        if block.page_num != 0:
            cover_end_idx = i
            break
        if _is_content_boundary(block):
            cover_end_idx = i
            break
        cover.blocks.append(block)
    else:
        cover_end_idx = len(blocks)

    if cover.blocks:
        sections.append(cover)
        position += 1

    # ---- Body: all blocks from cover_end_idx onwards (incl. rest of page 0) ----
    current: Section | None = None

    for block in blocks[cover_end_idx:]:

        # Treat as a stage direction if fully italic OR if it starts italic and
        # the text is an adoption line.  Some PDFs render the parenthetical
        # "(resolution X/Y)" in non-italic, making all_italic=False even though
        # the semantics are identical.
        is_stage = block.all_italic or (
            block.italic_start and bool(_ADOPTION_RE.search(block.text.strip()))
        )
        if is_stage:
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
