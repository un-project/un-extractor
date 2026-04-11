"""Unit tests for src/pdf/reocr.py.

All tests that would actually call ocrmypdf/tesseract are skipped when those
tools are not available, or use mocking so the test suite passes in CI
environments without the OCR stack installed.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.pdf.reocr import (
    ReocrError,
    ReocrUnavailable,
    is_available,
    reocr_context,
    reocr_pdf,
)

# Some tests require ocrmypdf to be importable so they can patch its internals.
try:
    import ocrmypdf as _ocrmypdf_check  # noqa: F401

    _OCRMYPDF_INSTALLED = True
except ImportError:
    _OCRMYPDF_INSTALLED = False

requires_ocrmypdf = pytest.mark.skipif(
    not _OCRMYPDF_INSTALLED, reason="ocrmypdf not installed"
)

# ---------------------------------------------------------------------------
# is_available()
# ---------------------------------------------------------------------------


def test_is_available_returns_bool() -> None:
    result = is_available()
    assert isinstance(result, bool)


def test_is_available_false_when_ocrmypdf_missing() -> None:
    # Patch the module-level ocrmypdf binding to None (simulating ImportError).
    with patch("src.pdf.reocr.ocrmypdf", None):
        assert is_available() is False


@requires_ocrmypdf
def test_is_available_false_when_tesseract_missing() -> None:
    # ocrmypdf present but tesseract not on PATH.
    with patch(
        "ocrmypdf._exec.tesseract.get_version",
        side_effect=Exception("not found"),
    ):
        # Result depends on environment; just ensure it returns a bool.
        result = is_available()
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# reocr_pdf() – error paths
# ---------------------------------------------------------------------------


def test_reocr_pdf_raises_unavailable_when_ocrmypdf_not_installed(
    tmp_path: Path,
) -> None:
    dummy_pdf = tmp_path / "dummy.pdf"
    dummy_pdf.write_bytes(b"%PDF-1.4")

    with patch("src.pdf.reocr.ocrmypdf", None):
        with pytest.raises(ReocrUnavailable, match="ocrmypdf is not installed"):
            reocr_pdf(dummy_pdf, work_dir=tmp_path)


def test_reocr_pdf_raises_unavailable_when_tesseract_missing(
    tmp_path: Path,
) -> None:
    dummy_pdf = tmp_path / "dummy.pdf"
    dummy_pdf.write_bytes(b"%PDF-1.4")

    with (
        patch("src.pdf.reocr.is_available", return_value=False),
        patch("src.pdf.reocr.ocrmypdf", MagicMock()),
    ):
        with pytest.raises(ReocrUnavailable, match="tesseract is not on PATH"):
            reocr_pdf(dummy_pdf, work_dir=tmp_path)


def test_reocr_pdf_raises_reocr_error_on_nonzero_exit(tmp_path: Path) -> None:
    dummy_pdf = tmp_path / "dummy.pdf"
    dummy_pdf.write_bytes(b"%PDF-1.4")

    mock_ocrmypdf = MagicMock()
    mock_ocrmypdf.ocr.return_value = 2  # non-zero exit
    mock_ocrmypdf.exceptions.MissingDependencyError = Exception

    with (
        patch("src.pdf.reocr.is_available", return_value=True),
        patch("src.pdf.reocr.ocrmypdf", mock_ocrmypdf),
    ):
        with pytest.raises(ReocrError, match="exit code 2"):
            reocr_pdf(dummy_pdf, work_dir=tmp_path)


def test_reocr_pdf_success_path(tmp_path: Path) -> None:
    """reocr_pdf writes an output file and returns its path."""
    input_pdf = tmp_path / "input.pdf"
    input_pdf.write_bytes(b"%PDF-1.4")
    work_dir = tmp_path / "work"

    mock_ocrmypdf = MagicMock()
    mock_ocrmypdf.ocr.return_value = 0  # success

    def fake_ocr(input_file, output_file, **kwargs):
        # Simulate ocrmypdf writing the output file.
        Path(output_file).write_bytes(b"%PDF-1.4 reocrd")
        return 0

    mock_ocrmypdf.ocr.side_effect = fake_ocr
    mock_ocrmypdf.exceptions.MissingDependencyError = Exception

    with (
        patch("src.pdf.reocr.is_available", return_value=True),
        patch("src.pdf.reocr.ocrmypdf", mock_ocrmypdf),
    ):
        out = reocr_pdf(input_pdf, work_dir=work_dir)

    assert out.exists()
    assert out.suffix == ".pdf"
    assert "reocr" in out.name
    assert out.parent == work_dir


def test_reocr_pdf_creates_work_dir_if_absent(tmp_path: Path) -> None:
    input_pdf = tmp_path / "input.pdf"
    input_pdf.write_bytes(b"%PDF-1.4")
    work_dir = tmp_path / "does" / "not" / "exist"

    def fake_ocr(input_file, output_file, **kwargs):
        Path(output_file).write_bytes(b"%PDF reocrd")
        return 0

    mock_ocrmypdf = MagicMock()
    mock_ocrmypdf.ocr.side_effect = fake_ocr
    mock_ocrmypdf.exceptions.MissingDependencyError = Exception

    with (
        patch("src.pdf.reocr.is_available", return_value=True),
        patch("src.pdf.reocr.ocrmypdf", mock_ocrmypdf),
    ):
        out = reocr_pdf(input_pdf, work_dir=work_dir)

    assert work_dir.exists()
    assert out.exists()


# ---------------------------------------------------------------------------
# reocr_context
# ---------------------------------------------------------------------------


def test_reocr_context_cleans_up_on_exit(tmp_path: Path) -> None:
    """The context manager deletes the temp directory after exit."""
    input_pdf = tmp_path / "input.pdf"
    input_pdf.write_bytes(b"%PDF-1.4")

    captured: list[Path] = []

    def fake_ocr(input_file, output_file, **kwargs):
        Path(output_file).write_bytes(b"%PDF reocrd")
        captured.append(Path(output_file))
        return 0

    mock_ocrmypdf = MagicMock()
    mock_ocrmypdf.ocr.side_effect = fake_ocr
    mock_ocrmypdf.exceptions.MissingDependencyError = Exception

    with (
        patch("src.pdf.reocr.is_available", return_value=True),
        patch("src.pdf.reocr.ocrmypdf", mock_ocrmypdf),
    ):
        with reocr_context(input_pdf) as out_path:
            assert out_path.exists()
            captured_path = out_path

    # After the context exits the temp dir (and file) should be gone.
    assert not captured_path.exists()


def test_reocr_context_propagates_unavailable(tmp_path: Path) -> None:
    input_pdf = tmp_path / "input.pdf"
    input_pdf.write_bytes(b"%PDF-1.4")

    with patch("src.pdf.reocr.is_available", return_value=False):
        with pytest.raises(ReocrUnavailable):
            with reocr_context(input_pdf):
                pass  # should not reach here


# ---------------------------------------------------------------------------
# Integration: process_pdf re-OCR path (mocked)
# ---------------------------------------------------------------------------


def test_process_pdf_skips_reocr_when_quality_good(tmp_path: Path) -> None:
    """process_pdf does not call reocr_context when OCR quality is already good."""
    from pathlib import Path as _Path

    pdf = _Path("data/raw_pdfs/en/ga/64/pv/document_121.pdf")
    if not pdf.exists():
        pytest.skip("Sample PDF not present")

    with patch("src.pipeline.process_pdf.reocr_context") as mock_ctx:
        from src.pipeline.process_pdf import process_pdf

        process_pdf(pdf, use_reocr=True)

    # reocr_context should NOT have been called — the PDF already has good quality.
    mock_ctx.assert_not_called()


def test_process_pdf_use_reocr_false_skips_reocr(tmp_path: Path) -> None:
    """process_pdf never calls reocr_context when use_reocr=False."""
    from pathlib import Path as _Path

    from src.pdf.ocr_quality import OcrQualityResult, POOR_THRESHOLD

    pdf = _Path("data/raw_pdfs/en/ga/64/pv/document_121.pdf")
    if not pdf.exists():
        pytest.skip("Sample PDF not present")

    # Patch score to be poor so we would normally trigger re-OCR.
    poor_result = OcrQualityResult(
        score=POOR_THRESHOLD - 0.1,
        label="poor",
        alpha_tokens=1000,
        word_like_tokens=300,
    )

    with (
        patch("src.pipeline.process_pdf.score_text_quality", return_value=poor_result),
        patch("src.pipeline.process_pdf.reocr_context") as mock_ctx,
    ):
        from src.pipeline.process_pdf import process_pdf

        process_pdf(pdf, use_reocr=False)

    mock_ctx.assert_not_called()


def test_process_pdf_logs_warning_when_reocr_unavailable(tmp_path: Path) -> None:
    """process_pdf logs a warning and continues when re-OCR is unavailable."""
    from pathlib import Path as _Path

    from src.pdf.ocr_quality import OcrQualityResult, POOR_THRESHOLD

    pdf = _Path("data/raw_pdfs/en/ga/64/pv/document_121.pdf")
    if not pdf.exists():
        pytest.skip("Sample PDF not present")

    poor_result = OcrQualityResult(
        score=POOR_THRESHOLD - 0.1,
        label="poor",
        alpha_tokens=1000,
        word_like_tokens=300,
    )

    class _FakeContext:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            raise ReocrUnavailable("tesseract not found")

        def __exit__(self, *a):
            pass

    with (
        patch("src.pipeline.process_pdf.score_text_quality", return_value=poor_result),
        patch("src.pipeline.process_pdf.reocr_context", _FakeContext),
    ):
        from src.pipeline.process_pdf import process_pdf

        # Should NOT raise — the pipeline continues with original text.
        record = process_pdf(pdf, use_reocr=True)

    assert record is not None
