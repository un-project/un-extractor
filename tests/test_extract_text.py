"""Unit tests for src/pdf/extract_text.py — column layout detection."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.pdf.extract_text import (
    _TWO_COLUMN_MIN_RIGHT_FRACTION,
    _extract_page_blocks,
)


# ---------------------------------------------------------------------------
# Helpers: build fake PyMuPDF page objects
# ---------------------------------------------------------------------------


def _span(text: str, bold: bool = False, italic: bool = False) -> dict[str, Any]:
    flags = (0x10 if bold else 0) | (0x02 if italic else 0)
    return {"text": text, "flags": flags, "font": "Times"}


def _block(x0: float, y0: float, text: str = "word") -> dict[str, Any]:
    """Build a minimal PyMuPDF text-block dict at position (x0, y0)."""
    return {
        "type": 0,
        "bbox": (x0, y0, x0 + 100, y0 + 20),
        "lines": [{"spans": [_span(text)]}],
    }


def _image_block(x0: float, y0: float) -> dict[str, Any]:
    return {"type": 1, "bbox": (x0, y0, x0 + 50, y0 + 50)}


def _make_page(
    blocks: list[dict[str, Any]], width: float = 600.0, height: float = 800.0
) -> Any:
    """Return a minimal fake PyMuPDF page object."""
    page = MagicMock()
    page.rect = SimpleNamespace(width=width, height=height)
    page.get_text.return_value = {"blocks": blocks}
    return page


# ---------------------------------------------------------------------------
# Column classification
# ---------------------------------------------------------------------------


class TestSingleColumnDetection:
    """Pages where almost all blocks are in the left half → single-column."""

    def test_all_left_blocks_classified_single_column(self) -> None:
        # 10 blocks all at x0=50 (well left of midpoint 300)
        blocks = [_block(50.0, float(i * 30)) for i in range(10)]
        page = _make_page(blocks, width=600.0)
        result = _extract_page_blocks(page, page_num=0)
        assert len(result) == 10

    def test_single_column_reading_order_top_to_bottom(self) -> None:
        """Blocks in a single-column page must be returned top-to-bottom."""
        # Create blocks at varying y positions, all in left half
        raw = [
            _block(50.0, 300.0, "third"),
            _block(50.0, 100.0, "first"),
            _block(50.0, 200.0, "second"),
        ]
        page = _make_page(raw, width=600.0)
        result = _extract_page_blocks(page, page_num=0)
        texts = [tb.text.strip() for tb in result]
        assert texts == ["first", "second", "third"]

    def test_threshold_boundary_is_single_column(self) -> None:
        """Exactly at the threshold — treated as single-column (strict <)."""
        # 10 blocks: 8 left, 2 right → right_fraction = 0.20 == threshold
        # Since the condition is < threshold (not <=), 0.20 is two-column.
        # 1 right out of 10 → 0.10 < 0.20 → single-column
        blocks = [_block(50.0, float(i * 30)) for i in range(9)]
        blocks.append(_block(400.0, 0.0, "right"))  # 1 right out of 10
        page = _make_page(blocks, width=600.0)
        result = _extract_page_blocks(page, page_num=0)
        assert len(result) == 10

    def test_single_column_with_far_right_italic_block(self) -> None:
        """Far-right italic blocks (e.g. 'Provisional' on SC cover pages) are
        sorted by y0 into the stream in single-column mode; they do NOT go to
        the end. The cover-section boundary logic in detect_sections handles
        them via the _DOC_STATUS_LABEL_RE exception instead."""
        # body blocks start at y0=100; Provisional is at y0=50 (near top)
        main = [_block(50.0, 100.0 + float(i * 30), f"body{i}") for i in range(9)]
        provisional = _block(500.0, 50.0, "Provisional")  # far right, near top
        page = _make_page(main + [provisional], width=600.0)
        result = _extract_page_blocks(page, page_num=0)
        # Single-column: all blocks sorted by y0; Provisional (y=50) comes
        # before body0 (y=100)
        texts = [tb.text.strip() for tb in result]
        assert texts[0] == "Provisional"
        assert texts[1] == "body0"


class TestTwoColumnDetection:
    """Pages with enough right-half blocks → two-column, left before right."""

    def test_balanced_left_right_classified_two_column(self) -> None:
        # 5 left blocks, 5 right blocks → right_fraction = 0.50
        left = [_block(50.0, float(i * 30), f"L{i}") for i in range(5)]
        right = [_block(350.0, float(i * 30), f"R{i}") for i in range(5)]
        page = _make_page(left + right, width=600.0)
        result = _extract_page_blocks(page, page_num=0)
        texts = [tb.text.strip() for tb in result]
        # Left blocks come first (all at x0=50 < 300), then right blocks
        assert texts[:5] == ["L0", "L1", "L2", "L3", "L4"]
        assert texts[5:] == ["R0", "R1", "R2", "R3", "R4"]

    def test_two_column_each_column_sorted_top_to_bottom(self) -> None:
        """Within each column, blocks must be top-to-bottom."""
        left = [_block(50.0, 200.0, "L-bottom"), _block(50.0, 50.0, "L-top")]
        right = [_block(350.0, 180.0, "R-bottom"), _block(350.0, 30.0, "R-top")]
        page = _make_page(left + right, width=600.0)
        result = _extract_page_blocks(page, page_num=0)
        texts = [tb.text.strip() for tb in result]
        assert texts == ["L-top", "L-bottom", "R-top", "R-bottom"]

    def test_right_fraction_at_threshold_is_two_column(self) -> None:
        """right_fraction == _TWO_COLUMN_MIN_RIGHT_FRACTION → two-column."""
        # Need exactly 20% right blocks
        n = 10
        k = round(_TWO_COLUMN_MIN_RIGHT_FRACTION * n)  # 2
        left = [_block(50.0, float(i * 30)) for i in range(n - k)]
        right = [_block(400.0, float(i * 30)) for i in range(k)]
        page = _make_page(left + right, width=600.0)
        result = _extract_page_blocks(page, page_num=0)
        # Two-column: right blocks come after left blocks
        assert len(result) == n


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_page_returns_empty_list(self) -> None:
        page = _make_page([], width=600.0)
        result = _extract_page_blocks(page, page_num=0)
        assert result == []

    def test_image_blocks_are_skipped(self) -> None:
        blocks = [_image_block(50.0, 50.0), _block(50.0, 100.0, "text")]
        page = _make_page(blocks, width=600.0)
        result = _extract_page_blocks(page, page_num=0)
        assert len(result) == 1
        assert result[0].text.strip() == "text"

    def test_only_image_blocks_returns_empty_list(self) -> None:
        blocks = [_image_block(50.0, float(i * 30)) for i in range(5)]
        page = _make_page(blocks, width=600.0)
        result = _extract_page_blocks(page, page_num=0)
        assert result == []

    def test_page_num_propagated(self) -> None:
        page = _make_page([_block(50.0, 100.0)], width=600.0)
        result = _extract_page_blocks(page, page_num=7)
        assert result[0].page_num == 7


# ---------------------------------------------------------------------------
# Constant sanity
# ---------------------------------------------------------------------------


def test_threshold_constant_is_sensible() -> None:
    assert 0.0 < _TWO_COLUMN_MIN_RIGHT_FRACTION < 0.5
