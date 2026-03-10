"""Column-aware text extraction from UN verbatim record PDFs.

UN documents use a two-column layout on every body page.  PyMuPDF's
default ``get_text()`` reads top-to-bottom across the full page width,
mixing the two columns.  This module splits each page at the horizontal
midpoint and processes the left column before the right.

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


def _is_bold(span: dict[str, Any]) -> bool:
    flags: int = span.get("flags", 0)
    font: str = span.get("font", "").lower()
    return bool(flags & _BOLD_FLAG) or "bold" in font


def _is_italic(span: dict[str, Any]) -> bool:
    flags: int = span.get("flags", 0)
    font: str = span.get("font", "").lower()
    return bool(flags & _ITALIC_FLAG) or "italic" in font or "oblique" in font


def _block_to_textblock(block: dict[str, Any], page_num: int) -> TextBlock | None:
    """Convert a PyMuPDF text block dict into a ``TextBlock``.

    Returns ``None`` for image blocks or empty blocks.
    """
    if block.get("type") != 0:  # 0 = text, 1 = image
        return None

    segments: list[FormattedSegment] = []
    for line in block.get("lines", []):
        for span in line.get("spans", []):
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
    )


def _extract_page_blocks(page: Any, page_num: int) -> list[TextBlock]:
    """Extract ``TextBlock`` objects from one page in two-column reading order."""
    mid_x: float = page.rect.width / 2.0

    raw: dict[str, Any] = page.get_text("dict")
    all_blocks: list[dict[str, Any]] = raw.get("blocks", [])

    left_blocks: list[dict[str, Any]] = []
    right_blocks: list[dict[str, Any]] = []

    for block in all_blocks:
        if block.get("type") != 0:
            continue
        x0: float = block["bbox"][0]
        if x0 < mid_x:
            left_blocks.append(block)
        else:
            right_blocks.append(block)

    # Sort each column strictly top-to-bottom.
    left_blocks.sort(key=lambda b: b["bbox"][1])
    right_blocks.sort(key=lambda b: b["bbox"][1])

    result: list[TextBlock] = []
    for block in left_blocks + right_blocks:
        tb = _block_to_textblock(block, page_num)
        if tb is not None:
            result.append(tb)
    return result


def extract_pages(pdf_path: Path) -> list[list[TextBlock]]:
    """Extract all pages from *pdf_path* as lists of ``TextBlock`` objects.

    Returns a list indexed by page number (0-based).  Each element is an
    ordered list of ``TextBlock`` objects in two-column reading order.

    Raises ``FileNotFoundError`` if the path does not exist.
    """
    if not pdf_path.exists():
        raise FileNotFoundError(pdf_path)

    doc: Any = fitz.open(str(pdf_path))
    try:
        return [
            _extract_page_blocks(doc[page_num], page_num)
            for page_num in range(len(doc))
        ]
    finally:
        doc.close()
