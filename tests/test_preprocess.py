"""Unit tests for src/pdf/preprocess.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest

from src.pdf.preprocess import (
    BINARIZE_BLOCK,
    BINARIZE_C,
    BORDER_FRACTION,
    DENOISE_H,
    RENDER_DPI,
    _binarize,
    _mask_borders,
    _to_gray,
    is_available,
    preprocess_page,
    preprocess_pdf,
)

# Skip tests that call cv2 directly when opencv-python is not installed.
requires_cv2 = pytest.mark.skipif(
    not is_available(), reason="opencv-python not installed"
)

# ---------------------------------------------------------------------------
# Helper: create synthetic test images
# ---------------------------------------------------------------------------


def _gray(  # type: ignore[type-arg]
    h: int = 100, w: int = 80, value: int = 200
) -> np.ndarray:
    return np.full((h, w), value, dtype=np.uint8)


def _rgb(h: int = 100, w: int = 80) -> np.ndarray:  # type: ignore[type-arg]
    img = np.zeros((h, w, 3), dtype=np.uint8)
    img[:, :] = [180, 200, 210]
    return img


def _rgba(h: int = 100, w: int = 80) -> np.ndarray:  # type: ignore[type-arg]
    img = np.zeros((h, w, 4), dtype=np.uint8)
    img[:, :] = [180, 200, 210, 255]
    return img


# ---------------------------------------------------------------------------
# is_available
# ---------------------------------------------------------------------------


def test_is_available_returns_bool() -> None:
    assert isinstance(is_available(), bool)


@requires_cv2
def test_is_available_true_when_cv2_present() -> None:
    assert is_available() is True


def test_is_available_false_when_cv2_missing() -> None:
    with patch("src.pdf.preprocess.cv2", None):
        assert is_available() is False


# ---------------------------------------------------------------------------
# _to_gray
# ---------------------------------------------------------------------------


def test_to_gray_passthrough_2d() -> None:
    img = _gray()
    out = _to_gray(img)
    assert out.shape == (100, 80)
    assert out.dtype == np.uint8


@requires_cv2
def test_to_gray_from_rgb() -> None:
    img = _rgb()
    out = _to_gray(img)
    assert out.ndim == 2
    assert out.dtype == np.uint8


@requires_cv2
def test_to_gray_from_rgba() -> None:
    img = _rgba()
    out = _to_gray(img)
    assert out.ndim == 2
    assert out.dtype == np.uint8


# ---------------------------------------------------------------------------
# _mask_borders
# ---------------------------------------------------------------------------


def test_mask_borders_zeros_top_and_bottom() -> None:
    img = _gray(100, 80, value=128)
    out = _mask_borders(img, fraction=0.1)
    # Top and bottom 10 rows should be 255 (white)
    assert (out[:10, :] == 255).all()
    assert (out[-10:, :] == 255).all()


def test_mask_borders_zeros_left_and_right() -> None:
    img = _gray(100, 80, value=128)
    out = _mask_borders(img, fraction=0.1)
    # Left and right 8 cols should be 255
    assert (out[:, :8] == 255).all()
    assert (out[:, -8:] == 255).all()


def test_mask_borders_center_unchanged() -> None:
    img = _gray(100, 80, value=50)
    out = _mask_borders(img, fraction=0.1)
    # Interior (10:90, 8:72) should still be 50
    assert (out[10:90, 8:72] == 50).all()


def test_mask_borders_fraction_zero() -> None:
    img = _gray(value=77)
    out = _mask_borders(img, fraction=0.0)
    # fraction=0 → border width clamped to 1 pixel each side
    # interior should be 77
    assert out[1:-1, 1:-1].min() == 77


def test_mask_borders_output_same_shape() -> None:
    img = _gray(200, 150)
    out = _mask_borders(img, fraction=BORDER_FRACTION)
    assert out.shape == img.shape


# ---------------------------------------------------------------------------
# _binarize
# ---------------------------------------------------------------------------


@requires_cv2
def test_binarize_output_is_binary() -> None:
    gray = _gray(100, 80, value=128)
    # Add some variation so threshold has something to work with
    gray[20:80, 20:60] = 30
    out = _binarize(gray)
    unique = set(np.unique(out).tolist())
    assert unique <= {0, 255}


@requires_cv2
def test_binarize_preserves_shape() -> None:
    gray = _gray(120, 90)
    out = _binarize(gray)
    assert out.shape == (120, 90)


# ---------------------------------------------------------------------------
# preprocess_page
# ---------------------------------------------------------------------------


@requires_cv2
def test_preprocess_page_returns_2d_uint8() -> None:
    img = _rgb()
    out = preprocess_page(img)
    assert out.ndim == 2
    assert out.dtype == np.uint8


@requires_cv2
def test_preprocess_page_from_grayscale() -> None:
    img = _gray()
    out = preprocess_page(img)
    assert out.ndim == 2


@requires_cv2
def test_preprocess_page_from_rgba() -> None:
    img = _rgba()
    out = preprocess_page(img)
    assert out.ndim == 2


@requires_cv2
def test_preprocess_page_border_masked() -> None:
    img = np.full((200, 160, 3), 50, dtype=np.uint8)
    out = preprocess_page(img, border_fraction=0.1, denoise=False, binarize=False)
    bh = max(1, int(200 * 0.1))
    bw = max(1, int(160 * 0.1))
    assert (out[:bh, :] == 255).all()
    assert (out[:, :bw] == 255).all()


@requires_cv2
def test_preprocess_page_no_denoise_no_binarize() -> None:
    img = np.full((100, 80, 3), 128, dtype=np.uint8)
    out = preprocess_page(img, border_fraction=0.0, denoise=False, binarize=False)
    # No processing except grayscale + border (fraction=0 → 1px border)
    assert out.ndim == 2


def test_preprocess_page_raises_when_cv2_missing() -> None:
    with patch("src.pdf.preprocess.cv2", None):
        with pytest.raises(ImportError, match="opencv-python"):
            preprocess_page(_rgb())


@requires_cv2
def test_preprocess_page_output_values_in_range() -> None:
    img = _rgb()
    out = preprocess_page(img)
    assert int(out.min()) >= 0
    assert int(out.max()) <= 255


# ---------------------------------------------------------------------------
# preprocess_pdf (mocked fitz)
# ---------------------------------------------------------------------------


def test_preprocess_pdf_raises_when_cv2_missing(tmp_path: Path) -> None:
    dummy = tmp_path / "in.pdf"
    dummy.write_bytes(b"%PDF-1.4")
    with patch("src.pdf.preprocess.cv2", None):
        with pytest.raises(ImportError, match="opencv-python"):
            preprocess_pdf(dummy, tmp_path / "out.pdf")


@requires_cv2
def test_preprocess_pdf_integration(tmp_path: Path) -> None:
    """End-to-end: preprocess a real sample PDF and verify output is a valid PDF."""
    pdf = Path("data/raw_pdfs/en/ga/31/pv/document_8.pdf")
    if not pdf.exists():
        pytest.skip("Sample PDF not present")

    out = tmp_path / "preprocessed.pdf"
    preprocess_pdf(pdf, out, dpi=72)  # low DPI for speed in tests

    assert out.exists()
    assert out.stat().st_size > 0
    # Output must start with the PDF magic number.
    assert out.read_bytes()[:4] == b"%PDF"


@requires_cv2
def test_preprocess_pdf_page_count_matches(tmp_path: Path) -> None:
    """Output PDF must have the same number of pages as the input."""
    import pymupdf as fitz

    pdf = Path("data/raw_pdfs/en/ga/64/pv/document_121.pdf")
    if not pdf.exists():
        pytest.skip("Sample PDF not present")

    out = tmp_path / "preprocessed.pdf"
    preprocess_pdf(pdf, out, dpi=72)

    doc_in = fitz.open(str(pdf))
    doc_out = fitz.open(str(out))
    n_in = len(doc_in)
    n_out = len(doc_out)
    doc_in.close()
    doc_out.close()

    assert n_in == n_out


# ---------------------------------------------------------------------------
# Constants sanity
# ---------------------------------------------------------------------------


def test_constants_are_sensible() -> None:
    assert 0 < BORDER_FRACTION < 0.5
    assert RENDER_DPI >= 150
    assert DENOISE_H > 0
    assert BINARIZE_BLOCK % 2 == 1, "BINARIZE_BLOCK must be odd"
    assert BINARIZE_C >= 0
