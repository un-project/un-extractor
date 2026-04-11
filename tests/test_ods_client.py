"""Unit tests for src/pdf/ods_client.py."""

from __future__ import annotations

import urllib.error
import urllib.request
from http.client import HTTPMessage
from unittest.mock import MagicMock, patch

import pytest

from src.pdf.ods_client import (
    OdsNoDocument,
    OdsUnavailable,
    fetch_ods_blocks,
    fetch_ods_html,
    html_to_blocks,
    ods_url,
)

# ---------------------------------------------------------------------------
# ods_url
# ---------------------------------------------------------------------------


class TestOdsUrl:
    def test_ga_symbol(self) -> None:
        assert ods_url("A/64/PV.121") == "https://undocs.org/en/A/64/PV.121"

    def test_sc_symbol(self) -> None:
        assert ods_url("S/PV.8422") == "https://undocs.org/en/S/PV.8422"

    def test_slashes_preserved(self) -> None:
        url = ods_url("A/65/PV.71")
        assert "/A/65/PV.71" in url


# ---------------------------------------------------------------------------
# html_to_blocks
# ---------------------------------------------------------------------------

_SIMPLE_HTML = """\
<html><body>
<p><b>Mr. Smith</b> (United Kingdom): Speech text here.</p>
<p>Second paragraph of speech.</p>
<p><i>The meeting was called to order.</i></p>
<p>Another ordinary paragraph.</p>
<p>Fifth paragraph to exceed minimum.</p>
</body></html>
"""

_BOLD_CSS_HTML = """\
<html><body>
<p><span style="font-weight:bold">Bold via CSS</span> normal text</p>
<p><span style="font-style:italic">Italic via CSS</span></p>
<p>Para three</p>
<p>Para four</p>
<p>Para five</p>
</body></html>
"""


class TestHtmlToBlocks:
    def test_returns_text_blocks(self) -> None:
        blocks = html_to_blocks(_SIMPLE_HTML)
        assert len(blocks) == 5
        texts = [b.text for b in blocks]
        assert any("Mr. Smith" in t for t in texts)
        assert any("Second paragraph" in t for t in texts)
        assert any("called to order" in t for t in texts)

    def test_bold_preserved(self) -> None:
        blocks = html_to_blocks(_SIMPLE_HTML)
        # First block should start with bold segment (Mr. Smith)
        first = blocks[0]
        assert first.bold_start

    def test_italic_preserved(self) -> None:
        blocks = html_to_blocks(_SIMPLE_HTML)
        italic_blocks = [b for b in blocks if b.all_italic]
        assert len(italic_blocks) == 1
        assert "called to order" in italic_blocks[0].text

    def test_bold_via_css(self) -> None:
        blocks = html_to_blocks(_BOLD_CSS_HTML)
        assert blocks[0].bold_start

    def test_italic_via_css(self) -> None:
        blocks = html_to_blocks(_BOLD_CSS_HTML)
        assert blocks[1].all_italic

    def test_page_num_zero(self) -> None:
        blocks = html_to_blocks(_SIMPLE_HTML)
        assert all(b.page_num == 0 for b in blocks)

    def test_y0_preserves_order(self) -> None:
        blocks = html_to_blocks(_SIMPLE_HTML)
        y0s = [b.y0 for b in blocks]
        assert y0s == sorted(y0s)

    def test_empty_paragraphs_skipped(self) -> None:
        html = "<html><body><p></p><p>   </p><p>Real content</p></body></html>"
        blocks = html_to_blocks(html)
        assert len(blocks) == 1
        assert blocks[0].text == "Real content"

    def test_script_and_style_ignored(self) -> None:
        html = (
            "<html><head><style>body{color:red}</style></head>"
            "<body><script>alert(1)</script><p>Visible</p></body></html>"
        )
        blocks = html_to_blocks(html)
        assert len(blocks) == 1
        assert blocks[0].text == "Visible"

    def test_div_creates_paragraph_boundary(self) -> None:
        html = "<html><body><div>First</div><div>Second</div></body></html>"
        blocks = html_to_blocks(html)
        assert len(blocks) == 2

    def test_br_creates_paragraph_boundary(self) -> None:
        html = "<html><body><p>Before<br>After</p></body></html>"
        blocks = html_to_blocks(html)
        # br flushes, so "Before" and "After" are separate paragraphs
        assert len(blocks) == 2

    def test_li_creates_paragraph_boundary(self) -> None:
        html = "<html><body><ul><li>Item one</li><li>Item two</li></ul></body></html>"
        blocks = html_to_blocks(html)
        assert len(blocks) == 2

    def test_large_document(self) -> None:
        paragraphs = "".join(
            f"<p>Paragraph number {i} with real content.</p>" for i in range(50)
        )
        html = f"<html><body>{paragraphs}</body></html>"
        blocks = html_to_blocks(html)
        assert len(blocks) == 50


# ---------------------------------------------------------------------------
# fetch_ods_html — mocked HTTP
# ---------------------------------------------------------------------------


def _make_mock_response(
    body: str,
    content_type: str = "text/html; charset=utf-8",
    status: int = 200,
) -> MagicMock:
    """Build a mock urllib response context manager."""
    resp = MagicMock()
    resp.headers = HTTPMessage()
    resp.headers["Content-Type"] = content_type
    resp.read.return_value = body.encode("utf-8")
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class TestFetchOdsHtml:
    def test_returns_html_string(self) -> None:
        mock_resp = _make_mock_response("<html><body>Hello</body></html>")
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = fetch_ods_html("A/64/PV.121")
        assert "Hello" in result

    def test_uses_correct_url(self) -> None:
        mock_resp = _make_mock_response("<html><body>X</body></html>")
        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
            fetch_ods_html("A/64/PV.121")
        req = mock_open.call_args[0][0]
        assert req.full_url == "https://undocs.org/en/A/64/PV.121"

    def test_404_raises_ods_no_document(self) -> None:
        exc = urllib.error.HTTPError(
            url="https://undocs.org/en/A/99/PV.1",
            code=404,
            msg="Not Found",
            hdrs=HTTPMessage(),
            fp=None,
        )
        with patch("urllib.request.urlopen", side_effect=exc):
            with pytest.raises(OdsNoDocument):
                fetch_ods_html("A/99/PV.1")

    def test_500_raises_ods_unavailable(self) -> None:
        exc = urllib.error.HTTPError(
            url="https://undocs.org/en/A/64/PV.121",
            code=500,
            msg="Server Error",
            hdrs=HTTPMessage(),
            fp=None,
        )
        with patch("urllib.request.urlopen", side_effect=exc):
            with pytest.raises(OdsUnavailable):
                fetch_ods_html("A/64/PV.121")

    def test_url_error_raises_ods_unavailable(self) -> None:
        exc = urllib.error.URLError(reason="Name or service not known")
        with patch("urllib.request.urlopen", side_effect=exc):
            with pytest.raises(OdsUnavailable):
                fetch_ods_html("A/64/PV.121")

    def test_non_html_content_type_raises_ods_no_document(self) -> None:
        mock_resp = _make_mock_response(
            b"\x25\x50\x44\x46".decode("latin-1"),
            content_type="application/pdf",
        )
        with patch("urllib.request.urlopen", return_value=mock_resp):
            with pytest.raises(OdsNoDocument):
                fetch_ods_html("A/64/PV.121")

    def test_charset_from_content_type(self) -> None:
        body_bytes = "résumé".encode("latin-1")
        mock_resp = MagicMock()
        mock_resp.headers = HTTPMessage()
        mock_resp.headers["Content-Type"] = "text/html; charset=iso-8859-1"
        mock_resp.read.return_value = body_bytes
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = fetch_ods_html("A/64/PV.121")
        assert "résumé" in result


# ---------------------------------------------------------------------------
# fetch_ods_blocks
# ---------------------------------------------------------------------------

_ENOUGH_PARAGRAPHS_HTML = "\n".join(
    f"<p>Paragraph {i} with sufficient real words here.</p>" for i in range(10)
)
_FULL_HTML = f"<html><body>{_ENOUGH_PARAGRAPHS_HTML}</body></html>"


class TestFetchOdsBlocks:
    def test_returns_blocks(self) -> None:
        with patch("src.pdf.ods_client.fetch_ods_html", return_value=_FULL_HTML):
            blocks = fetch_ods_blocks("A/64/PV.121")
        assert len(blocks) == 10

    def test_too_few_paragraphs_raises_ods_no_document(self) -> None:
        sparse_html = "<html><body><p>Only one paragraph.</p></body></html>"
        with patch("src.pdf.ods_client.fetch_ods_html", return_value=sparse_html):
            with pytest.raises(OdsNoDocument):
                fetch_ods_blocks("A/64/PV.121")

    def test_propagates_ods_unavailable(self) -> None:
        with patch(
            "src.pdf.ods_client.fetch_ods_html",
            side_effect=OdsUnavailable("network down"),
        ):
            with pytest.raises(OdsUnavailable):
                fetch_ods_blocks("A/64/PV.121")

    def test_propagates_ods_no_document(self) -> None:
        with patch(
            "src.pdf.ods_client.fetch_ods_html",
            side_effect=OdsNoDocument("HTTP 404"),
        ):
            with pytest.raises(OdsNoDocument):
                fetch_ods_blocks("A/64/PV.121")
