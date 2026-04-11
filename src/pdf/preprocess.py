"""Image pre-processing pipeline for scanned UN meeting PDFs.

Applies a sequence of image operations to each page *before* Tesseract sees it:

1. **Grayscale conversion** — single-channel input for all subsequent steps.
2. **Border masking** — zeros out a configurable margin on all four sides to
   remove punch-hole shadows, binding shadows, and scanner edge artefacts that
   confuse column detection.
3. **Denoising** — ``cv2.fastNlMeansDenoising`` removes scanner speckle and
   JPEG compression artefacts without blurring text strokes.
4. **Adaptive binarization** — ``cv2.adaptiveThreshold`` (Gaussian, 11-pixel
   blocks) handles uneven illumination across the page.

Deskew is intentionally left to ``ocrmypdf`` (which wraps ``unpaper``/``leptonica``)
rather than reimplemented here; Tesseract 5 also corrects slight rotations
autonomously.

Entry points
------------
``preprocess_page(img)``
    Apply the full pipeline to one page image (numpy array, any channel count).
    Returns an 8-bit grayscale numpy array ready to feed to Tesseract.

``preprocess_pdf(input_path, output_path)``
    Render every page of *input_path* at 300 DPI, apply the pipeline, and write
    the cleaned grey images to *output_path* as a new PDF.  The output PDF
    contains only image pages; pass it to ``reocr_pdf()`` for OCR.

Dependencies
------------
* ``opencv-python-headless`` — ``pip install opencv-python-headless``
* ``numpy`` — already a transitive dependency via scipy/etc.
* ``pymupdf`` — already required by the pipeline.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import numpy as np

log = logging.getLogger(__name__)

# Optional: cv2 is checked at call-time so importing this module never fails.
try:
    import cv2  # type: ignore[import]
except ImportError:  # pragma: no cover
    cv2 = None  # type: ignore[assignment]

try:
    import pymupdf as fitz  # type: ignore[import]
except ImportError:  # pragma: no cover
    try:
        import fitz  # type: ignore[import]
    except ImportError:
        fitz = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Tuneable defaults
# ---------------------------------------------------------------------------

# Resolution for rendering PDF pages to bitmaps.
RENDER_DPI: int = 300

# Fraction of page width/height to blank on each edge.
# At 300 DPI on A4 (~2480 px wide):  0.03 → ~74 px  on each side.
BORDER_FRACTION: float = 0.03

# cv2.fastNlMeansDenoising tunables.
DENOISE_H: int = 10  # filter strength; 10 is a safe default for scanner speckle
DENOISE_TEMPLATE: int = 7  # template window size (pixels)
DENOISE_SEARCH: int = 21  # search window size (pixels)

# cv2.adaptiveThreshold tunables.
BINARIZE_BLOCK: int = 11  # neighbourhood size; must be odd
BINARIZE_C: int = 2  # constant subtracted from the mean


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------


def is_available() -> bool:
    """Return ``True`` if opencv-python (cv2) and numpy are importable."""
    return cv2 is not None and np is not None


# ---------------------------------------------------------------------------
# Per-page pipeline
# ---------------------------------------------------------------------------


def _to_gray(img: np.ndarray) -> np.ndarray:  # type: ignore[type-arg]
    """Convert *img* to 8-bit grayscale regardless of input channels."""
    if img.ndim == 2:
        return img.astype(np.uint8)
    if img.shape[2] == 4:
        # RGBA — drop alpha, convert RGB
        img = img[:, :, :3]
    if img.shape[2] == 3:
        return cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
    return img[:, :, 0].astype(np.uint8)


def _mask_borders(
    gray: np.ndarray,  # type: ignore[type-arg]
    fraction: float = BORDER_FRACTION,
) -> np.ndarray:  # type: ignore[type-arg]
    """Zero out the border band on all four sides.

    Removes punch-hole shadows (left margin), binding shadows (typically left
    or right), and scanner-edge artefacts that confuse Tesseract's column
    layout analysis.
    """
    h, w = gray.shape
    bh = max(1, int(h * fraction))
    bw = max(1, int(w * fraction))
    out = gray.copy()
    out[:bh, :] = 255  # top
    out[-bh:, :] = 255  # bottom
    out[:, :bw] = 255  # left
    out[:, -bw:] = 255  # right
    return out


def _denoise(gray: np.ndarray) -> np.ndarray:  # type: ignore[type-arg]
    """Reduce scanner speckle with ``fastNlMeansDenoising``."""
    return cv2.fastNlMeansDenoising(  # type: ignore[no-any-return]
        gray,
        None,
        h=float(DENOISE_H),
        templateWindowSize=DENOISE_TEMPLATE,
        searchWindowSize=DENOISE_SEARCH,
    )


def _binarize(gray: np.ndarray) -> np.ndarray:  # type: ignore[type-arg]
    """Convert to binary using adaptive Gaussian thresholding.

    Handles uneven illumination across the page (common in flatbed scans).
    """
    return cv2.adaptiveThreshold(  # type: ignore[no-any-return]
        gray,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        BINARIZE_BLOCK,
        BINARIZE_C,
    )


def preprocess_page(
    img: np.ndarray,  # type: ignore[type-arg]
    *,
    border_fraction: float = BORDER_FRACTION,
    denoise: bool = True,
    binarize: bool = True,
) -> np.ndarray:  # type: ignore[type-arg]
    """Apply the full pre-processing pipeline to one page image.

    Parameters
    ----------
    img:
        Page rendered as a numpy array (H × W × C, uint8, any colour space).
    border_fraction:
        Fraction of each edge to blank (default: ``BORDER_FRACTION``).
    denoise:
        Apply ``fastNlMeansDenoising`` (recommended for scanned PDFs).
    binarize:
        Apply adaptive Gaussian threshold (recommended for scanned PDFs).

    Returns
    -------
    numpy.ndarray
        8-bit single-channel (grayscale) image, ready for Tesseract.

    Raises
    ------
    ImportError
        If ``opencv-python`` is not installed.
    """
    if cv2 is None:
        raise ImportError(
            "opencv-python is required for image pre-processing: "
            "pip install opencv-python-headless"
        )

    gray = _to_gray(img)
    gray = _mask_borders(gray, fraction=border_fraction)
    if denoise:
        gray = _denoise(gray)
    if binarize:
        gray = _binarize(gray)
    return gray


# ---------------------------------------------------------------------------
# PDF-level entry point
# ---------------------------------------------------------------------------


def preprocess_pdf(
    input_path: Path,
    output_path: Path,
    *,
    dpi: int = RENDER_DPI,
    border_fraction: float = BORDER_FRACTION,
    denoise: bool = True,
    binarize: bool = True,
) -> None:
    """Render every page of *input_path*, pre-process, and write to *output_path*.

    The output PDF contains only cleaned greyscale image pages and has no text
    layer.  Pass it to ``reocr_pdf()`` to produce a text layer with Tesseract.

    Parameters
    ----------
    input_path:
        Path to the original (possibly poor-quality) PDF.
    output_path:
        Destination path for the pre-processed image-only PDF.
    dpi:
        Resolution for rendering pages to bitmaps.
    border_fraction:
        Fraction of each edge to blank per page.
    denoise:
        Apply ``fastNlMeansDenoising`` per page.
    binarize:
        Apply adaptive Gaussian threshold per page.

    Raises
    ------
    ImportError
        If opencv-python or pymupdf is not installed.
    """
    if cv2 is None:
        raise ImportError(
            "opencv-python is required for image pre-processing: "
            "pip install opencv-python-headless"
        )
    if fitz is None:  # pragma: no cover
        raise ImportError("pymupdf is required: pip install pymupdf")

    doc_in: Any = fitz.open(str(input_path))
    doc_out: Any = fitz.open()

    zoom = dpi / 72.0  # 72 pt/inch is PyMuPDF's default base resolution
    mat = fitz.Matrix(zoom, zoom)

    for page_num in range(len(doc_in)):
        page = doc_in[page_num]
        pix = page.get_pixmap(matrix=mat, colorspace=fitz.csRGB)

        # Convert pixmap to numpy → pre-process → back to pixmap
        arr = np.frombuffer(pix.samples, dtype=np.uint8).reshape(
            pix.height, pix.width, pix.n
        )
        cleaned = preprocess_page(
            arr,
            border_fraction=border_fraction,
            denoise=denoise,
            binarize=binarize,
        )

        # Wrap the cleaned array back into a PyMuPDF Pixmap.
        # Grayscale (n=1) pixmaps use csGRAY; samples must be contiguous bytes.
        clean_bytes = np.ascontiguousarray(cleaned).tobytes()
        clean_pix = fitz.Pixmap(
            fitz.csGRAY,
            pix.width,
            pix.height,
            clean_bytes,
            False,
        )

        # Insert as a new page at the same physical size (in points at 72 dpi).
        page_width_pt = pix.width / zoom
        page_height_pt = pix.height / zoom
        new_page = doc_out.new_page(width=page_width_pt, height=page_height_pt)
        new_page.insert_image(
            fitz.Rect(0, 0, page_width_pt, page_height_pt),
            pixmap=clean_pix,
        )

        log.debug("Preprocessed page %d of %s", page_num, input_path.name)

    n_pages = len(doc_in)
    doc_in.close()
    doc_out.save(str(output_path))
    doc_out.close()
    log.info("Preprocessed PDF written: %s (%d pages)", output_path.name, n_pages)
