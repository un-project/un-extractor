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

from src.extraction.country_aliases import normalize_country_name
from src.models import CountryVote, Resolution, StageDirection, TextBlock
from src.structure.detect_sections import Section, _stage_direction_type

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Adoption line — five patterns:
#
# 1. Named symbol:  "Draft resolution A/64/L.72 was adopted (resolution 64/299)."
# 2. Roman numeral: "Draft resolution I was adopted (resolution 65/206)."
#                   "Draft resolution II was adopted (resolution 65/207)."
# 3. Amendment:     "The amendment (A/65/L.53) was adopted by N votes to M."
# 4. Generic:       "The draft decision was adopted."
# 5. No symbol:     "Draft resolution was adopted by 113 votes …"  (recent format)
#
# Group layout:
#   1 – "resolution"/"decision"  (cases 1/2)
#   2 – draft symbol or Roman numeral  (cases 1/2)
#   3 – "resolution"/"decision"  (optional adopted clause, cases 1/2)
#   4 – adopted symbol  (cases 1/2)
#   5 – amendment symbol  (case 3)
#   6 – "resolution"/"decision"  (optional adopted clause, case 4)
#   7 – adopted symbol  (case 4)
#   8 – "resolution"/"decision"  (optional adopted clause, case 5)
#   9 – adopted symbol  (case 5)
_ADOPTION_RE = re.compile(
    r"(?:"
    # Cases 1 & 2: "Draft (resolution|decision) <SYMBOL> was adopted"
    r"Draft\s+(resolution|decision)\s+((?:(?:A|S)/\S+?)|[IVXLCDM]+)"
    r"(?:,\s*as\s+orally\s+corrected,)?"
    r"\s+was\s+adopted"
    r"(?:\s+\((resolution|decision)\s+(\S+?)\))?"
    r"|"
    # Case 3: "The amendment (A/65/L.53) was adopted"
    r"The\s+amendment\s+\(((?:A|S)/\S+?)\)\s+was\s+adopted" r"|"
    # Case 4: "The draft (resolution|decision) was adopted"
    r"The\s+draft\s+(?:resolution|decision)\s+was\s+adopted"
    r"(?:\s+\((resolution|decision)\s+(\S+?)\))?"
    r"|"
    # Case 5 (recent): "Draft (resolution|decision) was adopted" — symbol absent
    # from this line; draft_symbol recovered from the preceding resolution header.
    # Vote totals may appear between "was adopted" and "(resolution X/Y)".
    r"Draft\s+(?:resolution|decision)\s+was\s+adopted"
    r"(?:.*?\((resolution|decision)\s+(\S+?)\))?"
    r")",
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

# Symbol extracted from a preceding bold header block,
# e.g. "Draft resolution (A/65/L.71)".
# Used as a fallback when the adoption line itself carries no symbol.
_SYMBOL_FROM_CONTEXT_RE = re.compile(r"([AS]/[^)\s,]+)", re.IGNORECASE)

# Resolution title — President announces "entitled 'Title'" before the vote.
# Matches both ASCII and Unicode typographic quotes.
# Two sub-patterns to handle different orderings:
#   A: "Draft resolution SYMBOL[,] [is] entitled <QUOTE>Title<QUOTE>"
#   B: bare "entitled <QUOTE>Title<QUOTE>" (fallback)
_OPEN_QUOTE = r"""["'\u201c\u2018]"""
_CLOSE_QUOTE = r"""["'\u201d\u2019]"""
_ENTITLED_ANCHORED_RE = re.compile(
    r"draft\s+(?:resolution|decision)\s+\S+"  # symbol (any)
    r"(?:,\s+|\s+is\s+|\s+)"
    r"entitled\s+" + _OPEN_QUOTE + r"(.+?)" + _CLOSE_QUOTE,
    re.IGNORECASE | re.DOTALL,
)
_ENTITLED_RE = re.compile(
    r"entitled\s+" + _OPEN_QUOTE + r"(.+?)" + _CLOSE_QUOTE,
    re.IGNORECASE | re.DOTALL,
)

# Signal that a recorded vote was taken (appears as its own italic line)
_RECORDED_VOTE_SIGNAL_RE = re.compile(
    r"A\s+recorded\s+vote\s+was\s+taken", re.IGNORECASE
)

# Per-country vote section headers — used to locate the start of each list.
_IN_FAVOUR_RE = re.compile(r"(?:^|\n)\s*In\s+favour\s*:\s*", re.IGNORECASE)
_AGAINST_RE = re.compile(r"(?:^|\n)\s*Against\s*:\s*", re.IGNORECASE)
_ABSTAINING_RE = re.compile(r"(?:^|\n)\s*Abstaining\s*:\s*", re.IGNORECASE)

# Marks the end of a country-vote section (next header or adoption/note lines).
# \n\s* handles block texts that start with a leading space (e.g. ' Draft …').
_VOTE_SECTION_STOP_RE = re.compile(
    r"\n\s*(?:In\s+favour|Against|Abstaining|Draft\s+res|The\s+draft|The\s+amend"
    r"|was adopted|\[)",
    re.IGNORECASE,
)


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
    return [normalize_country_name(p) for p in parts if p]


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

    # Determine the search region.  In the newer PDF format country lists
    # appear *before* the adoption line; in the older format they appear
    # after.  Restricting the search to the correct side prevents adjacent
    # votes' country lists from leaking in via _following() blocks.
    adoption_m = re.search(r"was adopted", full_text, re.IGNORECASE)
    if adoption_m:
        pre_text = full_text[: adoption_m.start()]
        post_text = full_text[adoption_m.end() :]
        # Newer format: at least one vote-category header precedes the adoption.
        _any_header = re.compile(
            r"(?:^|\n)(?:In\s+favour|Against|Abstaining)\s*:", re.IGNORECASE
        )
        if _any_header.search(pre_text):
            full_text = pre_text
        else:
            # Older format: country lists follow the adoption line.
            full_text = post_text

    def _section_text(header_re: re.Pattern[str]) -> str:
        """Return everything from *header_re* to the next section boundary."""
        m = header_re.search(full_text)
        if not m:
            return ""
        start = m.end()
        stop = _VOTE_SECTION_STOP_RE.search(full_text, start)
        raw = full_text[start : stop.start() if stop else len(full_text)]
        # Collapse all whitespace (including newlines from wrapped blocks)
        # into single spaces so split-across-line names are rejoined.
        return re.sub(r"\s+", " ", raw).strip()

    for country in _parse_country_list(_section_text(_IN_FAVOUR_RE)):
        votes.append(CountryVote(country=country, vote_position="yes"))
    for country in _parse_country_list(_section_text(_AGAINST_RE)):
        votes.append(CountryVote(country=country, vote_position="no"))
    for country in _parse_country_list(_section_text(_ABSTAINING_RE)):
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
    preceding_text: str = "",
) -> Resolution | None:
    """Parse a ``Resolution`` from an adoption stage-direction text.

    *surrounding_blocks* are the blocks that follow the adoption line
    (needed to find per-country vote lists for recorded votes).

    Handles three vote-total positions:
    - Totals on the adoption line itself (older format).
    - Totals in the first few surrounding blocks (older format).
    - Totals *after* country lists in surrounding blocks (newer format where
      country lists appear before the summary line).
    """
    m = _ADOPTION_RE.search(text)
    if not m:
        return None

    # Extract draft symbol from whichever capture group matched.
    # See _ADOPTION_RE docstring for the full group layout.
    draft_symbol: str = (m.group(2) or m.group(5) or "").rstrip(".,;")
    if not draft_symbol and preceding_text:
        pm = _SYMBOL_FROM_CONTEXT_RE.search(preceding_text)
        if pm:
            draft_symbol = pm.group(1).rstrip(".,;)")
    draft_symbol = draft_symbol or "unknown"
    # Groups 4, 7, 9 are the adopted symbol for cases 1/2, 4, 5 respectively.
    adopted_symbol: str | None = m.group(4) or m.group(7) or m.group(9)
    if adopted_symbol:
        adopted_symbol = adopted_symbol.rstrip(".,;)")

    # Determine if a recorded vote signal is present in surrounding blocks
    # ("A recorded vote was taken." appears as a separate italic line before
    # the country lists in the newer PDF format).
    # Only count the signal as belonging to *this* vote if it appears before
    # the adoption line — a signal appearing after the adoption line comes
    # from a subsequent vote and must not contaminate this resolution.
    surrounding_text = "\n".join(b.text for b in surrounding_blocks)
    adoption_pos_in_ctx = surrounding_text.lower().find("was adopted")
    signal_m = _RECORDED_VOTE_SIGNAL_RE.search(surrounding_text)
    has_recorded_signal = bool(
        signal_m and (adoption_pos_in_ctx < 0 or signal_m.start() < adoption_pos_in_ctx)
    )

    # Look for vote totals in:
    # 1. The adoption line itself + first few blocks (old format)
    # 2. Anywhere in the surrounding blocks (new format: totals after lists)
    early_context = text + " " + " ".join(b.text for b in surrounding_blocks[:5])
    yes, no, abstain = _extract_vote_totals(early_context)

    if yes is None and (has_recorded_signal or _RECORDED_VOTE_SIGNAL_RE.search(text)):
        # Totals appear at the end of the country lists — scan all blocks
        yes, no, abstain = _extract_vote_totals(surrounding_text)

    if yes is not None or has_recorded_signal:
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


def extract_resolution_title(context: str, draft_symbol: str) -> str | None:
    """Return the title for *draft_symbol* from surrounding context text.

    Searches for the President's announcement pattern::

        Draft resolution A/76/L.86, entitled "Financing for peacebuilding".
        Draft resolution I is entitled "Follow-up to …".

    First tries an anchored search where the symbol appears on the same line
    as "entitled".  Falls back to the last bare "entitled '…'" match in the
    context (last rather than first so that text about earlier resolutions in
    the same context window does not shadow the current one).
    """
    if not context:
        return None

    # Try anchored: "Draft resolution SYMBOL ... entitled 'Title'"
    for m in _ENTITLED_ANCHORED_RE.finditer(context):
        raw_sym = m.group(0).split()[2].rstrip(",")
        # Accept if the captured symbol text is a suffix/match of draft_symbol
        if (
            raw_sym.upper() == draft_symbol.upper()
            or draft_symbol.upper().endswith(raw_sym.upper())
            or raw_sym.upper().endswith(draft_symbol.upper())
        ):
            return m.group(1).strip()

    # Fallback: last "entitled 'Title'" in the context
    last: re.Match[str] | None = None
    for m in _ENTITLED_RE.finditer(context):
        last = m
    if last:
        return last.group(1).strip()

    return None


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
