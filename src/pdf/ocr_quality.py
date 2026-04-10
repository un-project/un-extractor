"""OCR quality scoring for UN verbatim record PDFs.

Computes a heuristic score in [0.0, 1.0] that estimates whether the embedded
text layer in a PDF is usable or is a garbage/stale OCR layer.

Algorithm
---------
For each whitespace-delimited token in the document text:

* An *alpha token* is any token that contains at least one ASCII alphabetic
  character.
* A *word-like token* is an alpha token where:
  - at least two characters are ASCII alphabetic, **and**
  - at least 50 % of all characters are ASCII alphabetic.

Score = word_like_count / max(1, alpha_token_count)

A document with clean English text scores ≥ 0.85.  A document whose embedded
text layer is a garbage scan (random byte sequences, symbol-heavy noise) scores
below 0.40.

Thresholds (configurable at module level)
-----------------------------------------
GOOD_THRESHOLD      Score ≥ this  → "good"   (pipeline runs normally)
POOR_THRESHOLD      Score ≥ this  → "poor"   (re-OCR recommended)
                    Score  < this → "unusable" (re-OCR required)
MIN_ALPHA_TOKENS    If the document has fewer alpha tokens than this the score
                    is forced to 0.0 ("unusable") — the PDF has no readable
                    text layer at all.
"""

from __future__ import annotations

from typing import Literal, NamedTuple

from src.models import TextBlock

# ---------------------------------------------------------------------------
# Tuneable thresholds
# ---------------------------------------------------------------------------

GOOD_THRESHOLD: float = 0.70
POOR_THRESHOLD: float = 0.40
MIN_ALPHA_TOKENS: int = 50  # fewer → treat as image-only / no text layer


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class OcrQualityResult(NamedTuple):
    """Result of an OCR quality assessment."""

    score: float
    """Heuristic score in [0.0, 1.0].  Higher is better."""

    label: Literal["good", "poor", "unusable"]
    """Human-readable classification derived from *score*."""

    alpha_tokens: int
    """Number of tokens containing at least one alphabetic character."""

    word_like_tokens: int
    """Number of tokens that look like real words."""


def score_text_quality(blocks: list[TextBlock]) -> OcrQualityResult:
    """Compute an OCR quality score for the text extracted from a PDF.

    Parameters
    ----------
    blocks:
        Flat list of ``TextBlock`` objects as returned by
        ``src.pdf.extract_text.extract_pages`` (before *or* after cleaning —
        raw blocks are preferred so header/footer noise is included in the
        denominator and does not inflate the score).

    Returns
    -------
    OcrQualityResult
        Named tuple with ``score``, ``label``, ``alpha_tokens``, and
        ``word_like_tokens``.
    """
    all_text = " ".join(b.text for b in blocks)
    tokens = all_text.split()

    alpha_tokens = 0
    word_like = 0

    for token in tokens:
        alpha_count = sum(1 for c in token if c.isascii() and c.isalpha())
        if alpha_count == 0:
            continue
        alpha_tokens += 1
        if alpha_count >= 2 and alpha_count / len(token) >= 0.50:
            word_like += 1

    if alpha_tokens < MIN_ALPHA_TOKENS:
        return OcrQualityResult(
            score=0.0,
            label="unusable",
            alpha_tokens=alpha_tokens,
            word_like_tokens=word_like,
        )

    score = word_like / alpha_tokens
    label = _classify(score)
    return OcrQualityResult(
        score=round(score, 4),
        label=label,
        alpha_tokens=alpha_tokens,
        word_like_tokens=word_like,
    )


def _classify(score: float) -> Literal["good", "poor", "unusable"]:
    if score >= GOOD_THRESHOLD:
        return "good"
    if score >= POOR_THRESHOLD:
        return "poor"
    return "unusable"
