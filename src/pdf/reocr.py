"""Re-OCR fallback for poor-quality embedded text layers.

When the OCR quality score (``src.pdf.ocr_quality``) falls below
``POOR_THRESHOLD``, the embedded text layer is unreliable.  This module
provides a fallback that:

1. Optionally pre-processes each page with OpenCV (border masking, denoising,
   adaptive binarization) via ``src.pdf.preprocess`` to produce cleaner images.
2. Runs ``ocrmypdf`` (Tesseract 5 + deskew) on the PDF.
3. Produces a new PDF with a clean text layer that feeds the existing PyMuPDF
   extraction pipeline unchanged.

External dependencies (not installed automatically)
----------------------------------------------------
* ``ocrmypdf``  — ``pip install ocrmypdf``
* ``tesseract`` — system package, e.g. ``apt install tesseract-ocr`` on Debian/Ubuntu.
  English language data (``tesseract-ocr-eng``) is needed for UN documents.

Call ``is_available()`` to check whether both are present before invoking
``reocr_pdf()``.  When either dependency is missing, ``reocr_pdf()`` raises
``ReocrUnavailable`` and the caller can fall back to the original text.
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

from src.pdf.preprocess import is_available as _preprocess_available
from src.pdf.preprocess import preprocess_pdf

log = logging.getLogger(__name__)

# Optional dependency: imported at module level so tests can patch it.
try:
    import ocrmypdf  # type: ignore[import]
    from ocrmypdf.exceptions import (  # type: ignore[import]
        MissingDependencyError as _MissingDependencyError,
    )
except ImportError:  # pragma: no cover
    ocrmypdf = None  # type: ignore[assignment]
    _MissingDependencyError = Exception  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ReocrUnavailable(Exception):
    """Raised when ocrmypdf or tesseract are not installed / not on PATH."""


class ReocrError(Exception):
    """Raised when re-OCR fails for reasons other than missing dependencies."""


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------


def is_available() -> bool:
    """Return ``True`` if both ocrmypdf (Python) and tesseract (CLI) are available.

    This is a cheap check — it does not run OCR.  Call it once at startup or
    before the first re-OCR attempt.
    """
    if ocrmypdf is None:
        return False

    try:
        from ocrmypdf._exec.tesseract import get_version  # type: ignore[import]

        get_version("tesseract")
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Core function
# ---------------------------------------------------------------------------


def reocr_pdf(
    input_path: Path,
    work_dir: Path | None = None,
    *,
    deskew: bool = True,
    language: str = "eng",
    jobs: int = 1,
    preprocess: bool = True,
) -> Path:
    """Re-OCR *input_path* and return the path of a new PDF with a clean text layer.

    The returned PDF is written inside *work_dir* (or a temporary directory if
    *work_dir* is ``None``).  The caller is responsible for deleting it when
    done.  Use the context-manager helper ``reocr_context`` to handle cleanup
    automatically.

    Parameters
    ----------
    input_path:
        Path to the original PDF.
    work_dir:
        Directory in which to write the re-OCR'd PDF.  Created if absent.
        If ``None``, a system temporary directory is used.
    deskew:
        Correct page tilt (recommended for scanned documents).
    language:
        Tesseract language code.  ``"eng"`` is sufficient for UN documents.
    jobs:
        Number of Tesseract workers.  Keep at 1 for batch pipeline runs to
        avoid over-subscribing CPU.
    preprocess:
        When ``True`` (default) and opencv-python is installed, apply border
        masking, denoising, and adaptive binarization to each page image before
        passing the PDF to Tesseract.  Falls back silently if opencv is absent.

    Returns
    -------
    Path
        Path to the output PDF with a Tesseract-generated text layer.

    Raises
    ------
    ReocrUnavailable
        If ocrmypdf or tesseract is not installed.
    ReocrError
        If ocrmypdf raises an unexpected error during processing.
    """
    if ocrmypdf is None:
        raise ReocrUnavailable("ocrmypdf is not installed: pip install ocrmypdf")

    if not is_available():
        raise ReocrUnavailable(
            "tesseract is not on PATH"
            " — install tesseract-ocr (e.g. apt install tesseract-ocr)"
        )

    if work_dir is not None:
        work_dir.mkdir(parents=True, exist_ok=True)
        out_path = work_dir / f"{input_path.stem}_reocr.pdf"
    else:
        import os

        fd, tmp = tempfile.mkstemp(suffix="_reocr.pdf", prefix=input_path.stem)
        os.close(fd)
        out_path = Path(tmp)

    # Optionally pre-process page images (border masking, denoising, binarize)
    # before Tesseract sees them.  The result is an image-only PDF; ocrmypdf
    # then adds the text layer on top of the cleaner images.
    ocr_input = input_path
    if preprocess and _preprocess_available():
        preprocessed_path = out_path.with_name(out_path.stem + "_prep.pdf")
        try:
            preprocess_pdf(input_path, preprocessed_path)
            ocr_input = preprocessed_path
            log.debug("Using pre-processed images for OCR: %s", preprocessed_path.name)
        except Exception as exc:
            log.warning(
                "Image pre-processing failed for %s (%s) — using original",
                input_path.name,
                exc,
            )
    elif preprocess and not _preprocess_available():
        log.debug(
            "opencv not available — skipping image pre-processing for %s",
            input_path.name,
        )

    log.info("Re-OCR: %s → %s", input_path.name, out_path)

    try:
        exit_code = ocrmypdf.ocr(
            ocr_input,
            out_path,
            language=language,
            force_ocr=True,  # bypass any existing (poor-quality) text layer
            deskew=deskew,
            optimize=0,  # skip image compression — we only want the text layer
            jobs=jobs,
            progress_bar=False,
        )
        if exit_code != 0:
            raise ReocrError(
                f"ocrmypdf returned exit code {exit_code} for {input_path}"
            )
    except (ReocrUnavailable, ReocrError):
        raise
    except _MissingDependencyError as exc:
        raise ReocrUnavailable(str(exc)) from exc
    except Exception as exc:
        raise ReocrError(f"ocrmypdf failed for {input_path}: {exc}") from exc
    finally:
        # Clean up the intermediate pre-processed PDF regardless of outcome.
        if ocr_input is not input_path and ocr_input.exists():
            ocr_input.unlink(missing_ok=True)

    log.info("Re-OCR complete: %s", out_path)
    return out_path


# ---------------------------------------------------------------------------
# Context-manager helper
# ---------------------------------------------------------------------------


class reocr_context:  # noqa: N801 — intentionally lowercase for ``with`` ergonomics
    """Context manager that runs re-OCR and deletes the output file on exit.

    Example::

        with reocr_context(pdf_path) as reocr_path:
            pages = extract_pages(reocr_path)
        # reocr_path is deleted here

    If re-OCR is unavailable, entering the context raises ``ReocrUnavailable``.
    """

    def __init__(
        self,
        input_path: Path,
        *,
        deskew: bool = True,
        language: str = "eng",
        preprocess: bool = True,
    ) -> None:
        self._input = input_path
        self._deskew = deskew
        self._language = language
        self._preprocess = preprocess
        self._tmp_dir: tempfile.TemporaryDirectory[str] | None = None
        self._out: Path | None = None

    def __enter__(self) -> Path:
        self._tmp_dir = tempfile.TemporaryDirectory(prefix="un_reocr_")
        self._out = reocr_pdf(
            self._input,
            work_dir=Path(self._tmp_dir.name),
            deskew=self._deskew,
            language=self._language,
            preprocess=self._preprocess,
        )
        return self._out

    def __exit__(self, *_: object) -> None:
        if self._tmp_dir is not None:
            self._tmp_dir.cleanup()
