"""Remove running headers, footers, and noise from extracted text blocks.

UN verbatim records repeat the document symbol in the page header and
print page numbers, document codes (``10-53066 (E)``), and a legal
disclaimer in the footer.  None of this carries content.

This module filters ``TextBlock`` objects based on vertical position and
text pattern matching.
"""

from __future__ import annotations

import re

from src.models import TextBlock

# ---------------------------------------------------------------------------
# Thresholds (fractions of page height)
# ---------------------------------------------------------------------------
# UN PDFs are typically A4 (841.9 pt) or US Letter (792 pt).
# We use fractions so the logic degrades gracefully for other page sizes.

_HEADER_FRACTION: float = 0.09  # top ~9 % of page
_FOOTER_FRACTION: float = 0.95  # bottom ~5 % of page
# Older scanned documents (pre-1990) have content extending to ~93 % of page
# height.  All true footer noise (page numbers, job codes, disclaimers) is
# caught by _is_noise() independently of position, so a tighter spatial band
# avoids cutting off legitimate content near the bottom margin.

# Typical A4 height; used only when page_height is not passed explicitly.
_DEFAULT_PAGE_HEIGHT_PT: float = 842.0

# ---------------------------------------------------------------------------
# Patterns for noise regardless of position
# ---------------------------------------------------------------------------

# Page numbers: "3", "3/31"
_PAGE_NUMBER_RE = re.compile(r"^\s*\d+(?:/\d+)?\s*$")

# Document print codes and page-number combinations:
#   Standalone code:     "10-53066 (E)", "22-58466"
#   Code + page:         "07-50429 2", "07-50429 14"
#   Page + code:         "3 07-50429", "15 07-50429"
#   Bare job numbers:    "*1070469*"
_DOC_CODE_RE = re.compile(
    r"^\s*(?:"
    # code (opt letter) (opt page or page/total fraction)
    r"\d{2}-\d{5}(?:\s*\([A-Z]\))?(?:\s+\d{1,3}(?:/\d+)?)?"
    r"|\d{1,3}(?:/\d+)?\s+\d{2}-\d{5}"  # page (or fraction) then code
    r"|\*\d{5,8}\*"  # *jobnum*
    r")\s*$"
)

# Boilerplate disclaimer / footer phrases and structural noise
_DISCLAIMER_FRAGMENTS: tuple[str, ...] = (
    "This record contains the text",
    "Corrections should be submitted",
    "consolidated corrigendum",
    "Please recycle",
    "Accessible document",
    "verbatimrecords@un.org",
    "Official Document System",
    "Official Records",  # repeated page header sometimes lands in body area
)

# Running page header used on body pages of newer documents (post-~2000):
#   "General Assembly Sixty-first session  107th plenary meeting Thursday, …"
# These are not caught by position alone when the PDF's actual page height
# differs from the hardcoded default (e.g. US Letter 792pt vs A4 842pt).
_RUNNING_HEADER_RE = re.compile(
    r"^(?:General\s+Assembly|Security\s+Council)\s+\S.{0,60}"
    r"(?:session|Session)(?:\s|$)",
)


def _is_noise(block: TextBlock) -> bool:
    """Return ``True`` if *block* carries no content."""
    text = block.text.strip()
    if not text:
        return True
    if _PAGE_NUMBER_RE.match(text):
        return True
    if _DOC_CODE_RE.match(text):
        return True
    for fragment in _DISCLAIMER_FRAGMENTS:
        if fragment in text:
            return True
    if _RUNNING_HEADER_RE.match(text):
        return True
    return False


def _in_header_or_footer(
    block: TextBlock,
    page_height: float = _DEFAULT_PAGE_HEIGHT_PT,
) -> bool:
    """Return ``True`` if *block* falls in the header or footer band."""
    # Use the height recorded on the block when available (set during extraction).
    h = block.page_height if block.page_height > 0 else page_height
    top_cutoff = h * _HEADER_FRACTION
    bottom_cutoff = h * _FOOTER_FRACTION
    return block.y0 < top_cutoff or block.y0 > bottom_cutoff


# Inline doc-code/page-number patterns that can appear embedded within
# larger blocks when a page break falls inside a paragraph.  These are
# stripped from block text rather than discarding the whole block.
_INLINE_CODE_RE = re.compile(
    r"\n\s*(?:"
    r"\d{2}-\d{5}(?:\s*\([A-Z]\))?(?:\s+\d{1,3}(?:/\d+)?)?"
    r"|\d{1,3}(?:/\d+)?\s+\d{2}-\d{5}"
    r")\s*\n",
    re.MULTILINE,
)


# Common short words that stay lowercase in title case (unless first word).
_LC_WORDS: frozenset[str] = frozenset(
    {
        "a",
        "an",
        "the",
        "of",
        "for",
        "in",
        "on",
        "at",
        "by",
        "to",
        "and",
        "or",
        "nor",
        "but",
        "as",
        "with",
        "from",
    }
)


def normalize_allcaps(text: str) -> str:
    """Convert an ALL-CAPS string to title case; leave mixed-case text unchanged.

    Applies a simple word-level title case where common function words
    (of, the, for, …) remain lowercase unless they start the string.
    If the text is not predominantly uppercase the original is returned.
    """
    alpha = [c for c in text if c.isalpha()]
    if not alpha or sum(1 for c in alpha if c.isupper()) / len(alpha) <= 0.8:
        return text
    words = text.split()
    out: list[str] = []
    for i, word in enumerate(words):
        low = word.lower()
        if i > 0 and low in _LC_WORDS:
            out.append(low)
        else:
            # Capitalize first letter, lowercase the rest (handles hyphens too)
            out.append(re.sub(r"[A-Za-z]+", lambda m: m.group().capitalize(), word))
    return " ".join(out)


def _strip_inline_noise(text: str) -> str:
    """Remove doc-code/page-number runs embedded within block text."""
    cleaned = _INLINE_CODE_RE.sub("\n", text)
    # Collapse triple+ newlines left by the removal.
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned


def clean_page(
    blocks: list[TextBlock],
    page_height: float = _DEFAULT_PAGE_HEIGHT_PT,
) -> list[TextBlock]:
    """Remove header, footer, and noise blocks from a single page."""
    return [
        b
        for b in blocks
        if not _in_header_or_footer(b, page_height) and not _is_noise(b)
    ]


def clean_pages(
    pages: list[list[TextBlock]],
    page_height: float = _DEFAULT_PAGE_HEIGHT_PT,
) -> list[list[TextBlock]]:
    """Clean all pages in a document."""
    return [clean_page(page, page_height) for page in pages]


def flatten_blocks(pages: list[list[TextBlock]]) -> list[TextBlock]:
    """Flatten a list-of-pages into a single ordered list of blocks."""
    return [block for page in pages for block in page]
