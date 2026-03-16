"""Extract speaker attribution and speech text from speaker-turn sections.

Speaker turn format in UN verbatim records:

    Mr. Alsaidi (Yemen): speech text …
    Mrs. Salazar-Mejía (Colombia) (spoke in Spanish): text …
    Mr. Dai Bing (China) (spoke in Chinese): text …
    The President (spoke in Arabic): text …
    The President: text …
    Ms. Sharma (Department for General Assembly …): text …

The name is **bold** in the original PDF; everything after the colon is
the speech text.  Speeches may span many paragraphs.
"""

from __future__ import annotations

import re

from src.extraction.country_aliases import normalize_country_name
from src.models import Speech, SpeakerInfo
from src.pdf.clean_text import _strip_inline_noise, normalize_allcaps
from src.structure.detect_sections import Section

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Matches the full speaker attribution up to and including the colon.
# Groups:
#   1 – title (Mr.|Mrs.|Ms.|Dr.|Prof.|H.E.)  or None
#   2 – name
#   3 – country / affiliation (first parenthetical)
#   4 – language note, e.g. "spoke in Spanish"  or None
_SPEAKER_ATTR_RE = re.compile(
    r"^"
    r"(?:(H\.E\.|Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+)?"  # optional title
    r"([\w\s\-\u00C0-\u024F\.]+?)"  # name (allows accented chars, hyphens)
    r"\s*\(([^)]+)\)"  # (country or affiliation)
    r"(?:\s*\(([^)]+)\))?"  # optional (spoke in Language)
    r"\s*:",
    re.IGNORECASE | re.UNICODE,
)

# Titular speakers: "The President", "The Secretary-General", etc.
_TITULAR_ATTR_RE = re.compile(
    r"^(The\s+(?:President|Secretary-General|Chair(?:man|woman|person)?|"
    r"Deputy\s+Secretary-General|Acting\s+President))"
    r"(?:\s*\(([^)]+)\))?"  # optional (spoke in Language)
    r"\s*:",
    re.IGNORECASE,
)

# Language note inside parentheses: "(spoke in French)"
_LANGUAGE_RE = re.compile(r"spoke\s+in\s+(\w+)", re.IGNORECASE)

# Group / bloc attribution in speech text
_ON_BEHALF_RE = re.compile(
    r"on\s+behalf\s+of\s+(?:the\s+)?([\w\s,\-]+?)(?:\s*[.,;]|\s+I\b)",
    re.IGNORECASE,
)

# Titular role names
_TITULAR_ROLES: frozenset[str] = frozenset(
    {
        "president",
        "secretary-general",
        "chairman",
        "chairwoman",
        "chairperson",
        "deputy secretary-general",
        "acting president",
    }
)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_language(paren_text: str | None) -> str | None:
    """Extract language name from a '(spoke in X)' string."""
    if not paren_text:
        return None
    m = _LANGUAGE_RE.search(paren_text)
    return m.group(1).capitalize() if m else None


def _infer_role(name: str, affiliation: str | None) -> str | None:
    """Infer speaker role from name and affiliation."""
    lower_name = name.lower().strip()
    for role in _TITULAR_ROLES:
        if role in lower_name:
            return role.title()
    if affiliation:
        lower_aff = affiliation.lower()
        if any(
            kw in lower_aff
            for kw in ("department", "office", "bureau", "division", "secretariat")
        ):
            return "Secretariat"
    return None


def parse_speaker_info(attribution_text: str) -> SpeakerInfo | None:
    """Parse a speaker attribution string into a ``SpeakerInfo``.

    Returns ``None`` if the text does not match a known attribution pattern.
    """
    text = attribution_text.strip()

    # Try titular (The President, The Secretary-General …)
    m = _TITULAR_ATTR_RE.match(text)
    if m:
        name = m.group(1).strip()
        lang = _parse_language(m.group(2))
        role = _infer_role(name, None)
        return SpeakerInfo(name=normalize_allcaps(name), country=None, language=lang, role=role)

    # Try regular speaker (Mr./Mrs./Ms. + country)
    m2 = _SPEAKER_ATTR_RE.match(text)
    if m2:
        title = m2.group(1)
        name = m2.group(2).strip()
        affiliation = m2.group(3).strip() if m2.group(3) else None
        lang = _parse_language(m2.group(4))

        # Handle "Name (spoke in Language) (Country):" — language note first.
        # When group(3) is itself a language note, swap the two parentheticals.
        if affiliation and _LANGUAGE_RE.search(affiliation):
            lang = _parse_language(affiliation)
            affiliation = m2.group(4).strip() if m2.group(4) else None

        # Determine if affiliation is a country or a UN department
        is_dept = affiliation and any(
            kw in affiliation.lower()
            for kw in ("department", "office", "bureau", "division", "secretariat")
        )

        country = None if is_dept else (normalize_country_name(affiliation) if affiliation else None)
        role = _infer_role(name, affiliation)

        full_name = normalize_allcaps(f"{title} {name}".strip() if title else name)
        return SpeakerInfo(
            name=full_name,
            title=title,
            country=country,
            language=lang,
            role=role,
        )

    return None


def _extract_on_behalf_of(text: str) -> str | None:
    """Look for 'on behalf of X' in the first paragraph of speech text."""
    m = _ON_BEHALF_RE.search(text[:500])
    return m.group(1).strip() if m else None


def _split_attribution_and_body(block_text: str) -> tuple[str, str]:
    """Split the first block of a speaker section into attribution and body.

    Returns ``(attribution_text, speech_body_text)``.
    The attribution is everything up to and including the first colon
    that follows the speaker name pattern.
    """
    # Work on the stripped version so that leading/trailing whitespace in the
    # raw PDF block text does not cause off-by-one errors when slicing.
    stripped = block_text.strip()
    for pattern in (_TITULAR_ATTR_RE, _SPEAKER_ATTR_RE):
        m = pattern.match(stripped)
        if m:
            end = m.end()
            return stripped[:end].strip(), stripped[end:].strip()
    # Fallback: split on first colon
    idx = stripped.find(":")
    if idx != -1:
        return stripped[: idx + 1].strip(), stripped[idx + 1 :].strip()
    return stripped, ""


# ---------------------------------------------------------------------------
# Section-level extraction
# ---------------------------------------------------------------------------


def extract_speech(section: Section, position: int) -> Speech | None:
    """Extract a ``Speech`` from a ``speaker_turn`` section.

    Returns ``None`` if speaker attribution cannot be parsed.
    """
    if not section.blocks:
        return None

    first_block_text = section.blocks[0].text
    attribution_text, first_body = _split_attribution_and_body(first_block_text)

    speaker = parse_speaker_info(attribution_text)
    if speaker is None:
        return None

    # Collect full speech text
    body_parts: list[str] = []
    if first_body.strip():
        body_parts.append(first_body.strip())
    for block in section.blocks[1:]:
        body_parts.append(block.text.strip())

    full_text = _strip_inline_noise("\n\n".join(p for p in body_parts if p))

    # Enrich with on_behalf_of if not already set
    if not speaker.on_behalf_of and full_text:
        speaker = speaker.model_copy(
            update={"on_behalf_of": _extract_on_behalf_of(full_text)}
        )

    return Speech(position=position, speaker=speaker, text=full_text)


def extract_speeches(sections: list[Section]) -> list[Speech]:
    """Extract all speeches from a list of sections."""
    speeches: list[Speech] = []
    pos = 0
    for section in sections:
        if section.section_type == "speaker_turn":
            speech = extract_speech(section, pos)
            if speech is not None:
                speeches.append(speech)
            pos += 1
    return speeches
