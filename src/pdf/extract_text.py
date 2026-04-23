"""Column-aware text extraction from UN verbatim record PDFs.

UN documents use a two-column layout on every body page.  PyMuPDF's
default ``get_text()`` reads top-to-bottom across the full page width,
mixing the two columns.  This module splits each page at the horizontal
midpoint and processes the left column before the right.

Early SC verbatim records (roughly pre-1970) were printed in a bilingual
format: the English transcript occupies the left column and the French
transcript occupies the right column.  When a bilingual layout is
detected the right column is discarded entirely so the caller only
receives English text.

The returned ``TextBlock`` objects carry rich formatting metadata
(bold / italic flags per segment) needed downstream to identify speaker
turns and stage directions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import pymupdf as fitz  # type: ignore[no-redef]  # PyMuPDF ≥ 1.24
except ImportError:  # pragma: no cover
    import fitz  # type: ignore[no-redef]  # noqa: F401

from src.models import FormattedSegment, TextBlock

# Fraction of page height that is considered "header" / "footer" area.
# These bands are stripped by clean_text, but we already track page_num
# so they can be filtered later.
_BOLD_FLAG: int = 0x10
_ITALIC_FLAG: int = 0x02

# Minimum fraction of text blocks whose left edge (x0) must fall to the
# right of the page midpoint for the page to be treated as two-column.
# Very early GA sessions (1–10, late 1940s) used single-column layouts;
# their blocks are almost all in the left half, so the fraction is near 0.
# Typical two-column pages have roughly equal numbers of left/right blocks,
# producing a fraction near 0.5.
_TWO_COLUMN_MIN_RIGHT_FRACTION: float = 0.20

# Bilingual layout detection: early SC documents have French in the right
# column.  If the right-column text contains more than this fraction of
# French-specific diacritic characters the page (and document) is treated
# as bilingual and the right column is suppressed.
_FRENCH_DIACRITICS: frozenset[str] = frozenset("éèêëàâçîïôùûüœæÉÈÊËÀÂÇÎÏÔÙÛÜŒÆ")
_BILINGUAL_FRENCH_THRESHOLD: float = 0.005  # >0.5 % diacritics → French column
_BILINGUAL_MIN_CHARS: int = 100  # minimum right-column chars needed to judge


def _is_bilingual_layout(all_blocks: list[dict[str, Any]], mid_x: float) -> bool:
    """Return True when the right half of the page looks like French text.

    Collects all span text whose left edge (x0) is ≥ *mid_x*, then checks
    whether the ratio of French diacritic characters exceeds the threshold.
    This reliably separates bilingual early-SC pages (~3 % diacritics) from
    English-only pages (0 %).
    """
    parts: list[str] = []
    for block in all_blocks:
        for line in block.get("lines", []):
            for span in line.get("spans", []):
                if span["bbox"][0] >= mid_x:
                    parts.append(span.get("text", ""))
    text = "".join(parts)
    if len(text) < _BILINGUAL_MIN_CHARS:
        return False
    french_count = sum(1 for c in text if c in _FRENCH_DIACRITICS)
    return (french_count / len(text)) > _BILINGUAL_FRENCH_THRESHOLD


def _detect_bilingual_doc(doc: Any) -> bool:
    """Return True if any of the first few pages shows a bilingual layout."""
    for page_num in range(1, min(6, len(doc))):
        page = doc[page_num]
        mid_x: float = page.rect.width / 2.0
        raw: dict[str, Any] = page.get_text("dict")
        all_blocks = [b for b in raw.get("blocks", []) if b.get("type") == 0]
        if _is_bilingual_layout(all_blocks, mid_x):
            return True
    return False


def _is_bold(span: dict[str, Any]) -> bool:
    flags: int = span.get("flags", 0)
    font: str = span.get("font", "").lower()
    return bool(flags & _BOLD_FLAG) or "bold" in font


def _is_italic(span: dict[str, Any]) -> bool:
    flags: int = span.get("flags", 0)
    font: str = span.get("font", "").lower()
    return bool(flags & _ITALIC_FLAG) or "italic" in font or "oblique" in font


def _block_to_textblock(
    block: dict[str, Any],
    page_num: int,
    page_height: float,
    max_x: float | None = None,
) -> TextBlock | None:
    """Convert a PyMuPDF text block dict into a ``TextBlock``.

    Returns ``None`` for image blocks or empty blocks.

    When *max_x* is supplied only spans whose left edge (x0) is strictly
    less than *max_x* are included.  This is used for bilingual documents
    to keep only the English (left-column) spans even inside blocks that
    straddle both columns.
    """
    if block.get("type") != 0:  # 0 = text, 1 = image
        return None

    segments: list[FormattedSegment] = []
    for line in block.get("lines", []):
        for span in line.get("spans", []):
            if max_x is not None and span["bbox"][0] >= max_x:
                continue  # right-column span — discard in bilingual mode
            text: str = span.get("text", "")
            if not text:
                continue
            segments.append(
                FormattedSegment(
                    text=text,
                    bold=_is_bold(span),
                    italic=_is_italic(span),
                )
            )
        # Add a space between lines within the same block so joined text
        # doesn't run words together.
        if segments and not segments[-1].text.endswith(" "):
            segments.append(FormattedSegment(text=" ", bold=False, italic=False))

    if not segments:
        return None

    bbox = block["bbox"]
    return TextBlock(
        segments=segments,
        page_num=page_num,
        y0=bbox[1],
        x0=bbox[0],
        page_height=page_height,
    )


def _extract_page_blocks(
    page: Any, page_num: int, bilingual: bool = False
) -> list[TextBlock]:
    """Extract ``TextBlock`` objects from one page in correct reading order.

    For two-column pages (the standard UN format) blocks are partitioned at
    the horizontal midpoint and sorted left-column-first.  For single-column
    pages (very early GA sessions) all blocks are sorted top-to-bottom without
    splitting, avoiding the half-empty pseudo-columns that would scramble
    reading order.

    When *bilingual* is ``True`` the page is treated as a bilingual
    English-left / French-right layout: only blocks whose left edge is in the
    left half are processed, and within those blocks any span whose left edge
    falls in the right half is discarded.  This is used for early SC verbatim
    records printed in parallel English/French columns.

    A page is classified as single-column when fewer than
    ``_TWO_COLUMN_MIN_RIGHT_FRACTION`` of its text blocks have their left edge
    (``x0``) to the right of the page midpoint.
    """
    mid_x: float = page.rect.width / 2.0
    height: float = page.rect.height

    raw: dict[str, Any] = page.get_text("dict")
    all_blocks: list[dict[str, Any]] = [
        b for b in raw.get("blocks", []) if b.get("type") == 0
    ]

    if not all_blocks:
        return []

    right_count: int = sum(1 for b in all_blocks if b["bbox"][0] >= mid_x)
    right_fraction: float = right_count / len(all_blocks)

    if bilingual:
        # Bilingual layout: keep only left-column blocks and filter out any
        # right-column spans that appear inside wide blocks straddling both
        # columns.
        left_blocks = sorted(
            [b for b in all_blocks if b["bbox"][0] < mid_x],
            key=lambda b: b["bbox"][1],
        )
        result: list[TextBlock] = []
        for block in left_blocks:
            tb = _block_to_textblock(block, page_num, height, max_x=mid_x)
            if tb is not None:
                result.append(tb)
        return result

    if right_fraction < _TWO_COLUMN_MIN_RIGHT_FRACTION:
        # Single-column layout: sort all blocks strictly top-to-bottom.
        ordered = sorted(all_blocks, key=lambda b: b["bbox"][1])
    else:
        # Two-column layout: left column first, then right column.
        left_blocks = [b for b in all_blocks if b["bbox"][0] < mid_x]
        right_blocks = [b for b in all_blocks if b["bbox"][0] >= mid_x]
        left_blocks.sort(key=lambda b: b["bbox"][1])
        right_blocks.sort(key=lambda b: b["bbox"][1])
        ordered = left_blocks + right_blocks

    result = []
    for block in ordered:
        tb = _block_to_textblock(block, page_num, height)
        if tb is not None:
            result.append(tb)
    return result


def extract_pages(pdf_path: Path) -> list[list[TextBlock]]:
    """Extract all pages from *pdf_path* as lists of ``TextBlock`` objects.

    Returns a list indexed by page number (0-based).  Each element is an
    ordered list of ``TextBlock`` objects in two-column reading order.

    For bilingual documents (early SC records with English left / French
    right) only the English (left) column is returned for every page.

    Raises ``FileNotFoundError`` if the path does not exist.
    """
    if not pdf_path.exists():
        raise FileNotFoundError(pdf_path)

    doc: Any = fitz.open(str(pdf_path))
    try:
        bilingual: bool = _detect_bilingual_doc(doc)
        return [
            _extract_page_blocks(doc[page_num], page_num, bilingual=bilingual)
            for page_num in range(len(doc))
        ]
    finally:
        doc.close()
