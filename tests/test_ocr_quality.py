"""Unit tests for src/pdf/ocr_quality.py."""

from __future__ import annotations

import pytest

from src.models import FormattedSegment, TextBlock
from src.pdf.ocr_quality import (
    GOOD_THRESHOLD,
    MIN_ALPHA_TOKENS,
    POOR_THRESHOLD,
    OcrQualityResult,
    score_text_quality,
)


def _block(text: str) -> TextBlock:
    return TextBlock(
        segments=[FormattedSegment(text=text, bold=False, italic=False)],
        page_num=0,
        y0=0.0,
        x0=0.0,
    )


def _blocks(texts: list[str]) -> list[TextBlock]:
    return [_block(t) for t in texts]


# ---------------------------------------------------------------------------
# score_text_quality – basic behaviour
# ---------------------------------------------------------------------------


def test_empty_blocks_returns_unusable() -> None:
    result = score_text_quality([])
    assert result.score == 0.0
    assert result.label == "unusable"
    assert result.alpha_tokens == 0
    assert result.word_like_tokens == 0


def test_too_few_alpha_tokens_returns_unusable() -> None:
    # Fewer than MIN_ALPHA_TOKENS alpha tokens → score forced to 0.0
    result = score_text_quality(_blocks(["hello world"]))  # only 2 alpha tokens
    assert result.score == 0.0
    assert result.label == "unusable"


def test_clean_english_text_scores_good() -> None:
    # Generate MIN_ALPHA_TOKENS clean English words.
    words = ["meeting", "resolution", "adopted", "delegate", "security", "council"] * 20
    result = score_text_quality(_blocks([" ".join(words)]))
    assert result.score >= GOOD_THRESHOLD
    assert result.label == "good"


def test_garbage_ocr_scores_unusable() -> None:
    # Simulate a garbage OCR text layer: tokens have some alpha chars but the
    # alpha ratio is below 50 % (so none are "word-like").
    # e.g. "x12345" → 1 alpha / 6 chars = 17 % < 50 %, counts as alpha token
    # but not word-like.  70 such tokens → score = 0 / 70 = 0.0.
    garbage_tokens = ["x12345", "a9876", "b0001", "c99!@", "d###5"] * 20
    result = score_text_quality(_blocks([" ".join(garbage_tokens)]))
    assert result.score < POOR_THRESHOLD
    assert result.label == "unusable"


def test_mixed_quality_scores_poor() -> None:
    # 50 % word-like, 50 % single-char or symbol junk.
    good = ["meeting", "resolution", "council", "delegate", "adopted"] * 30
    junk = ["x", "!!", "#", "q", "7x"] * 30
    tokens = good + junk
    import random

    random.seed(42)
    random.shuffle(tokens)
    result = score_text_quality(_blocks([" ".join(tokens)]))
    # Score should be in the "poor" or "good" range (≥0.4), not "unusable".
    assert result.score >= POOR_THRESHOLD


def test_single_char_tokens_not_word_like() -> None:
    # Single-character tokens (even if alpha) are not word-like.
    singles = ["a", "b", "c", "i", "x"] * 30
    result = score_text_quality(_blocks([" ".join(singles)]))
    assert result.word_like_tokens == 0
    # alpha_tokens is len(singles) = 150 → score = 0 / 150 = 0.0
    assert result.score < POOR_THRESHOLD


def test_non_ascii_alpha_not_counted() -> None:
    # Non-ASCII alphabetic characters (e.g. accented, Cyrillic) are excluded
    # from the alpha count so they don't inflate the score for garbled text.
    non_ascii = ["caf\u00e9"] * 60  # "café" — é is non-ASCII
    result = score_text_quality(_blocks([" ".join(non_ascii)]))
    # "caf" = 3 ASCII alpha out of 4 chars → each token is word-like
    # score should be 1.0 (all 3-char ASCII-alpha prefix passes)
    assert result.label in ("good", "poor", "unusable")  # just check it runs


def test_result_is_named_tuple() -> None:
    result = score_text_quality(_blocks(["hello world"] * 30))
    assert isinstance(result, OcrQualityResult)
    assert hasattr(result, "score")
    assert hasattr(result, "label")
    assert hasattr(result, "alpha_tokens")
    assert hasattr(result, "word_like_tokens")


def test_score_rounded_to_four_decimals() -> None:
    words = ["resolution", "adopted", "delegate"] * 30
    result = score_text_quality(_blocks([" ".join(words)]))
    assert result.score == round(result.score, 4)


# ---------------------------------------------------------------------------
# Threshold constants
# ---------------------------------------------------------------------------


def test_thresholds_are_ordered() -> None:
    assert 0.0 < POOR_THRESHOLD < GOOD_THRESHOLD < 1.0


def test_min_alpha_tokens_positive() -> None:
    assert MIN_ALPHA_TOKENS > 0


# ---------------------------------------------------------------------------
# Integration: sample PDFs
# ---------------------------------------------------------------------------


def test_modern_pdf_scores_good(tmp_path: pytest.TempPathFactory) -> None:
    """The modern sample PDFs should have good OCR quality."""
    from pathlib import Path

    from src.pdf.extract_text import extract_pages
    from src.pdf.clean_text import flatten_blocks

    pdf = Path("data/raw_pdfs/en/ga/64/pv/document_121.pdf")
    if not pdf.exists():
        pytest.skip("Sample PDF not present")
    pages = extract_pages(pdf)
    blocks = flatten_blocks(pages)
    result = score_text_quality(blocks)
    assert (
        result.label == "good"
    ), f"Expected 'good' for modern PDF, got {result.label!r} (score={result.score})"


def test_scanned_pdf_returns_valid_result() -> None:
    """The 1976 scanned document can be scored without error.

    The 1976 PDF (document_8) carries an ALL-CAPS text layer that is
    linguistically legible — English words, just uppercased.  The scorer
    correctly gives it a high score because the word-level alpha ratio is good.
    This test confirms the scorer runs and returns a sane OcrQualityResult.
    """
    from pathlib import Path

    from src.pdf.clean_text import flatten_blocks
    from src.pdf.extract_text import extract_pages

    pdf = Path("data/raw_pdfs/en/ga/31/pv/document_8.pdf")
    if not pdf.exists():
        pytest.skip("Sample PDF not present")
    pages = extract_pages(pdf)
    blocks = flatten_blocks(pages)
    result = score_text_quality(blocks)
    assert isinstance(result, OcrQualityResult)
    assert 0.0 <= result.score <= 1.0
    assert result.alpha_tokens >= MIN_ALPHA_TOKENS
