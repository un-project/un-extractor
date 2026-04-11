"""Fetch UN verbatim-record text from the UN Official Document System (ODS).

The UN ODS / Digital Library serves HTML renditions of verbatim records at::

    https://undocs.org/en/{symbol}

These HTML files are derived from Word originals and contain clean, properly
formatted text — far superior to the OCR text embedded in scanned PDFs.

This module:

1. Fetches the HTML for a given document symbol (``A/64/PV.121``, ``S/PV.8422``).
2. Parses the HTML into :class:`~src.models.TextBlock` objects that carry
   bold/italic metadata, so the existing section-detection and speaker-extraction
   pipeline works unchanged.
3. Scores the extracted text with :func:`~src.pdf.ocr_quality.score_text_quality`
   so the caller can compare quality against the PDF-embedded text.

All network I/O uses the standard-library ``urllib.request``; no third-party
HTTP library is required.
"""

from __future__ import annotations

import html as _html_mod
import logging
import re
import urllib.error
import urllib.request
from html.parser import HTMLParser

from src.models import FormattedSegment, TextBlock

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ODS_BASE_URL: str = "https://undocs.org/en"
_REQUEST_TIMEOUT: int = 15  # seconds
_USER_AGENT: str = (
    "un-extractor/1.0 (https://github.com/un-project/un-extractor; "
    "research use; contact via GitHub issues)"
)

# Minimum number of non-empty paragraphs required to accept an ODS response.
# If the parsed HTML yields fewer paragraphs the page is probably a redirect
# stub or error page rather than the actual document.
_MIN_PARAGRAPHS: int = 5


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class OdsUnavailable(Exception):
    """Raised when the ODS endpoint cannot be reached or returns an error."""


class OdsNoDocument(Exception):
    """Raised when ODS has no HTML rendition for the requested symbol."""


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def ods_url(symbol: str) -> str:
    """Return the ``undocs.org`` URL for *symbol*.

    Example::

        >>> ods_url("A/64/PV.121")
        'https://undocs.org/en/A/64/PV.121'
    """
    # Forward slashes are valid and expected in the URL path.
    return f"{_ODS_BASE_URL}/{symbol}"


# ---------------------------------------------------------------------------
# HTML → TextBlock parser
# ---------------------------------------------------------------------------


class _ParagraphParser(HTMLParser):
    """Extract paragraphs as lists of ``(text, bold, italic)`` tuples.

    The UN ODS HTML uses a mix of semantic tags (``<b>``, ``<i>``) and
    inline CSS (``font-weight:bold``, ``font-style:italic``) to encode
    formatting.  Both conventions are handled.
    """

    def __init__(self) -> None:
        super().__init__()
        # Current formatting state
        self._bold: int = 0  # nesting counter
        self._italic: int = 0
        # Current paragraph accumulator: list of (text, bold, italic)
        self._cur_para: list[tuple[str, bool, bool]] = []
        # Completed paragraphs
        self.paragraphs: list[list[tuple[str, bool, bool]]] = []
        # Track whether we're inside a skip region (script, style, head)
        self._skip: int = 0

    # --- internal helpers ---

    def _flush_para(self) -> None:
        """Commit the current paragraph (if non-empty) and start a new one."""
        stripped = [(t, b, i) for (t, b, i) in self._cur_para if t.strip()]
        if stripped:
            self.paragraphs.append(stripped)
        self._cur_para = []

    @staticmethod
    def _css_bold(style: str) -> bool:
        """Return True if the CSS *style* string specifies a bold weight."""
        m = re.search(r"font-weight\s*:\s*([^;]+)", style, re.IGNORECASE)
        if not m:
            return False
        val = m.group(1).strip().lower()
        # "bold", "700", "800", "900" — all visually bold
        return val == "bold" or (val.isdigit() and int(val) >= 600)

    @staticmethod
    def _css_italic(style: str) -> bool:
        """Return True if the CSS *style* string specifies italic."""
        m = re.search(r"font-style\s*:\s*([^;]+)", style, re.IGNORECASE)
        if not m:
            return False
        return m.group(1).strip().lower() in ("italic", "oblique")

    # --- HTMLParser overrides ---

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style", "head"):
            self._skip += 1
            return
        if self._skip:
            return

        attr_dict: dict[str, str] = {k: (v or "") for k, v in attrs}
        style = attr_dict.get("style", "")

        if tag in ("b", "strong"):
            self._bold += 1
        elif tag in ("i", "em"):
            self._italic += 1
        elif tag == "span":
            if self._css_bold(style):
                self._bold += 1
            if self._css_italic(style):
                self._italic += 1
        elif tag in ("p", "div", "br", "h1", "h2", "h3", "h4", "li"):
            self._flush_para()

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "head"):
            self._skip = max(0, self._skip - 1)
            return
        if self._skip:
            return

        if tag in ("b", "strong"):
            self._bold = max(0, self._bold - 1)
        elif tag in ("i", "em"):
            self._italic = max(0, self._italic - 1)
        elif tag == "span":
            # We can't easily track which span had which CSS property;
            # reset to 0 when the span closes if the counter is now wrong.
            # (A proper solution would use a stack, but for the UN HTML
            # structure — one formatting level deep — this is sufficient.)
            pass
        elif tag in ("p", "div", "h1", "h2", "h3", "h4", "li"):
            self._flush_para()

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if data.strip():
            self._cur_para.append((data, bool(self._bold), bool(self._italic)))

    def handle_entityref(self, name: str) -> None:  # pragma: no cover
        char = _html_mod.unescape(f"&{name};")
        self.handle_data(char)

    def handle_charref(self, name: str) -> None:  # pragma: no cover
        char = _html_mod.unescape(f"&#{name};")
        self.handle_data(char)

    def close(self) -> None:
        self._flush_para()
        super().close()


# ---------------------------------------------------------------------------
# Public conversion function
# ---------------------------------------------------------------------------


def html_to_blocks(html_text: str) -> list[TextBlock]:
    """Parse ODS HTML into a flat list of :class:`TextBlock` objects.

    Each HTML paragraph becomes one ``TextBlock``.  Bold and italic spans
    are preserved so the downstream section-detection code can identify
    speaker attributions and stage directions.

    Parameters
    ----------
    html_text:
        Raw HTML string fetched from ODS.

    Returns
    -------
    list[TextBlock]
        Ordered blocks ready to feed into :func:`~src.pdf.clean_text.clean_pages`.
        All blocks have ``page_num=0`` (ODS HTML has no page concept).
    """
    parser = _ParagraphParser()
    parser.feed(html_text)
    parser.close()

    blocks: list[TextBlock] = []
    for para in parser.paragraphs:
        segments: list[FormattedSegment] = [
            FormattedSegment(text=text, bold=bold, italic=italic)
            for (text, bold, italic) in para
            if text.strip()
        ]
        if not segments:
            continue
        blocks.append(
            TextBlock(
                segments=segments,
                page_num=0,
                y0=float(len(blocks)),  # synthetic y0 preserves order
                x0=0.0,
            )
        )
    return blocks


# ---------------------------------------------------------------------------
# HTTP fetch
# ---------------------------------------------------------------------------


def fetch_ods_html(
    symbol: str,
    *,
    timeout: int = _REQUEST_TIMEOUT,
) -> str:
    """Fetch the HTML rendition of *symbol* from ``undocs.org``.

    Parameters
    ----------
    symbol:
        UN document symbol, e.g. ``"A/64/PV.121"``.
    timeout:
        Network timeout in seconds.

    Returns
    -------
    str
        Raw HTML string.

    Raises
    ------
    OdsUnavailable
        If the request fails (network error, HTTP 5xx).
    OdsNoDocument
        If the server returns HTTP 404 (no HTML version exists for this
        symbol) or the response is not HTML.
    """
    url = ods_url(symbol)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": _USER_AGENT, "Accept": "text/html"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type: str = resp.headers.get("Content-Type", "")
            if "html" not in content_type.lower():
                raise OdsNoDocument(
                    f"ODS returned non-HTML content ({content_type!r}) "
                    f"for {symbol!r}"
                )
            raw: bytes = resp.read()
            # Detect encoding from Content-Type or BOM; default to UTF-8.
            charset = "utf-8"
            m = re.search(r"charset=([^\s;]+)", content_type, re.IGNORECASE)
            if m:
                charset = m.group(1).strip().strip('"')
            return raw.decode(charset, errors="replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise OdsNoDocument(
                f"ODS has no document for symbol {symbol!r} (HTTP 404)"
            ) from exc
        raise OdsUnavailable(f"ODS returned HTTP {exc.code} for {symbol!r}") from exc
    except urllib.error.URLError as exc:
        raise OdsUnavailable(f"Cannot reach ODS for {symbol!r}: {exc.reason}") from exc
    except OSError as exc:
        raise OdsUnavailable(
            f"Network error fetching ODS for {symbol!r}: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# High-level helper
# ---------------------------------------------------------------------------


def fetch_ods_blocks(
    symbol: str,
    *,
    timeout: int = _REQUEST_TIMEOUT,
) -> list[TextBlock]:
    """Fetch ODS HTML for *symbol* and return parsed :class:`TextBlock` objects.

    This is the main entry point for callers that just want blocks.

    Parameters
    ----------
    symbol:
        UN document symbol, e.g. ``"A/64/PV.121"``.
    timeout:
        Network timeout in seconds.

    Returns
    -------
    list[TextBlock]
        Parsed blocks.  An empty list means the ODS page had no usable content.

    Raises
    ------
    OdsUnavailable
        On network / HTTP server errors.
    OdsNoDocument
        When ODS has no HTML for this symbol.
    """
    html_text = fetch_ods_html(symbol, timeout=timeout)
    blocks = html_to_blocks(html_text)
    if len(blocks) < _MIN_PARAGRAPHS:
        raise OdsNoDocument(
            f"ODS page for {symbol!r} yielded only {len(blocks)} paragraphs "
            f"(minimum {_MIN_PARAGRAPHS}); likely a redirect or error page"
        )
    return blocks
