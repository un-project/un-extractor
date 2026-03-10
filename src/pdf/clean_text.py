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
_FOOTER_FRACTION: float = 0.91  # bottom ~9 % of page

# Typical A4 height; used only when page_height is not passed explicitly.
_DEFAULT_PAGE_HEIGHT_PT: float = 842.0

# ---------------------------------------------------------------------------
# Patterns for noise regardless of position
# ---------------------------------------------------------------------------

# Page numbers: "3", "3/31"
_PAGE_NUMBER_RE = re.compile(r"^\s*\d+(?:/\d+)?\s*$")

# Document print codes: "10-53066 (E)", "22-58466"
_DOC_CODE_RE = re.compile(r"^\s*\d{2}-\d{5}(?:\s*\([A-Z]\))?\s*$")

# Boilerplate disclaimer / footer phrases
_DISCLAIMER_FRAGMENTS: tuple[str, ...] = (
    "This record contains the text",
    "Corrections should be submitted",
    "consolidated corrigendum",
    "Please recycle",
    "Accessible document",
    "verbatimrecords@un.org",
    "Official Document System",
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
    return False


def _in_header_or_footer(
    block: TextBlock,
    page_height: float = _DEFAULT_PAGE_HEIGHT_PT,
) -> bool:
    """Return ``True`` if *block* falls in the header or footer band."""
    top_cutoff = page_height * _HEADER_FRACTION
    bottom_cutoff = page_height * _FOOTER_FRACTION
    return block.y0 < top_cutoff or block.y0 > bottom_cutoff


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
