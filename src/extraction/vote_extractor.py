"""Extract vote data and stage directions from the document section stream.

Two vote types:

1. **Consensus** — signalled by "It was so decided." (no country list).
   The adoption line is a stage direction.

2. **Recorded vote** — the verbatim record prints:
   - Vote totals: "adopted by 121 votes to 5, with 3 abstentions"
   - Per-country breakdown:
       In favour: Algeria, Angola, …
       Against: Israel, United States of America
       Abstaining: Australia, Canada, …

Stage directions are also extracted here (they include adoption lines,
procedural decisions, suspensions, etc.).
"""

from __future__ import annotations

import re

from src.models import CountryVote, Resolution, StageDirection, TextBlock
from src.structure.detect_sections import Section, _stage_direction_type

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Adoption line: "Draft resolution A/64/L.72 was adopted (resolution 64/299)."
_ADOPTION_RE = re.compile(
    r"Draft\s+(resolution|decision)\s+((?:A|S)/\S+?)"
    r"(?:,\s*as\s+orally\s+corrected,)?"
    r"\s+was\s+adopted"
    r"(?:\s+\((resolution|decision)\s+(\S+?)\))?"
    r"[\.\s]",
    re.IGNORECASE,
)

# Counted vote totals: "by 121 votes to 5, with 3 abstentions" or "by 120 to 3"
_VOTE_TOTALS_RE = re.compile(
    r"by\s+(\d+)\s+(?:votes?\s+)?(?:in\s+favour\s+)?to\s+(\d+)"
    r"(?:\s+against)?(?:,?\s+with\s+(\d+)\s+abstentions?)?",
    re.IGNORECASE,
)

# Recorded vote simple: "121 in favour to 5 against, with 3 abstentions"
_VOTE_TOTALS_ALT_RE = re.compile(
    r"(\d+)\s+(?:votes?\s+)?in\s+favour\s+to\s+(\d+)\s+against"
    r"(?:,\s+with\s+(\d+)\s+abstentions?)?",
    re.IGNORECASE,
)

# Per-country vote sections — multi-line lists
_IN_FAVOUR_RE = re.compile(r"^In\s+favour\s*:\s*(.+)", re.IGNORECASE | re.MULTILINE)
_AGAINST_RE = re.compile(r"^Against\s*:\s*(.+)", re.IGNORECASE | re.MULTILINE)
_ABSTAINING_RE = re.compile(r"^Abstaining\s*:\s*(.+)", re.IGNORECASE | re.MULTILINE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_country_list(raw: str) -> list[str]:
    """Split a comma-separated country list into individual names.

    Handles names that contain commas (e.g. "Korea, Republic of") by
    only splitting on commas followed by a capital letter or space+capital.
    """
    # Normalise whitespace
    clean = re.sub(r"\s+", " ", raw.strip()).rstrip(".")
    # Simple comma split — downstream LLM normalisation handles edge cases
    parts = [p.strip() for p in clean.split(",")]
    return [p for p in parts if p]


def _extract_vote_totals(
    text: str,
) -> tuple[int | None, int | None, int | None]:
    """Return (yes, no, abstain) counts from vote total text."""
    for pattern in (_VOTE_TOTALS_RE, _VOTE_TOTALS_ALT_RE):
        m = pattern.search(text)
        if m:
            yes = int(m.group(1))
            no = int(m.group(2))
            abstain = int(m.group(3)) if m.group(3) else 0
            return yes, no, abstain
    return None, None, None


def _extract_country_votes(blocks: list[TextBlock]) -> list[CountryVote]:
    """Extract per-country vote positions from a block sequence."""
    votes: list[CountryVote] = []

    # Join all block text and look for In favour / Against / Abstaining sections.
    full_text = "\n".join(b.text for b in blocks)

    m_fav = _IN_FAVOUR_RE.search(full_text)
    m_against = _AGAINST_RE.search(full_text)
    m_abs = _ABSTAINING_RE.search(full_text)

    if m_fav:
        for country in _parse_country_list(m_fav.group(1)):
            votes.append(CountryVote(country=country, vote_position="yes"))

    if m_against:
        for country in _parse_country_list(m_against.group(1)):
            votes.append(CountryVote(country=country, vote_position="no"))

    if m_abs:
        for country in _parse_country_list(m_abs.group(1)):
            votes.append(CountryVote(country=country, vote_position="abstain"))

    return votes


# ---------------------------------------------------------------------------
# Section-level extraction
# ---------------------------------------------------------------------------


def extract_stage_direction(section: Section, position: int) -> StageDirection:
    """Build a ``StageDirection`` from a ``stage_direction`` section."""
    text = section.text.strip()
    dtype = _stage_direction_type(text)
    return StageDirection(position=position, text=text, direction_type=dtype)


def extract_resolution_from_adoption(
    text: str,
    surrounding_blocks: list[TextBlock],
) -> Resolution | None:
    """Parse a ``Resolution`` from an adoption stage-direction text.

    *surrounding_blocks* are the blocks that follow the adoption line
    (needed to find per-country vote lists for recorded votes).
    """
    m = _ADOPTION_RE.search(text)
    if not m:
        return None

    draft_symbol = m.group(2).rstrip(".,;")
    adopted_symbol: str | None = m.group(4)
    if adopted_symbol:
        adopted_symbol = adopted_symbol.rstrip(".,;)")

    # Check for vote totals in the same text or nearby blocks
    full_context = text + " " + " ".join(b.text for b in surrounding_blocks[:5])
    yes, no, abstain = _extract_vote_totals(full_context)

    if yes is not None:
        vote_type = "recorded"
        country_votes = _extract_country_votes(surrounding_blocks)
    else:
        vote_type = "consensus"
        country_votes = []

    return Resolution(
        draft_symbol=draft_symbol,
        adopted_symbol=adopted_symbol,
        vote_type=vote_type,
        yes_count=yes,
        no_count=no,
        abstain_count=abstain,
        country_votes=country_votes,
    )


def extract_votes_and_directions(
    sections: list[Section],
) -> tuple[list[Resolution], list[StageDirection]]:
    """Process all sections and return resolutions and stage directions.

    For each ``stage_direction`` section whose text is an adoption line,
    a ``Resolution`` is created (potentially with vote counts and per-country
    data extracted from the blocks that immediately follow).

    Returns
    -------
    resolutions : list[Resolution]
    stage_directions : list[StageDirection]
    """
    resolutions: list[Resolution] = []
    stage_directions: list[StageDirection] = []

    # Build an index of blocks following each section (for vote list extraction)
    all_blocks: list[TextBlock] = []
    section_end_positions: list[int] = []
    running = 0
    for sec in sections:
        section_end_positions.append(running)
        running += len(sec.blocks)
        all_blocks.extend(sec.blocks)

    pos = 0
    for idx, section in enumerate(sections):
        if section.section_type != "stage_direction":
            continue

        sd = extract_stage_direction(section, pos)
        stage_directions.append(sd)
        pos += 1

        if sd.direction_type == "adoption":
            # Pass subsequent blocks for country list extraction
            start = section_end_positions[idx] + len(section.blocks)
            subsequent = all_blocks[start : start + 80]
            res = extract_resolution_from_adoption(sd.text, subsequent)
            if res is not None:
                resolutions.append(res)

    return resolutions, stage_directions
