#!/usr/bin/env python3
"""Fetch full text of GA resolutions from documents.un.org and store in the DB.

For every GA resolution that has an ``adopted_symbol`` but no ``full_text``,
this script:

1. Downloads the PDF from the UN Documents API:
   ``https://documents.un.org/api/symbol/access?s={symbol}&l=en&t=pdf``
2. Extracts plain text with PyMuPDF.
3. Writes the result to ``resolutions.full_text``.

Progress is committed every ``--batch`` resolutions so the script is safe to
interrupt and resume (already-populated rows are skipped).

Usage
-----
    python scripts/import_ga_resolution_texts.py
    python scripts/import_ga_resolution_texts.py --limit 100 --delay 0.5
    python scripts/import_ga_resolution_texts.py --dry-run
    python scripts/import_ga_resolution_texts.py --db postgresql://...
"""

from __future__ import annotations

import argparse
import io
import logging
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fitz  # noqa: E402  (PyMuPDF)

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402

log = logging.getLogger(__name__)

_API_URL = (
    "https://documents.un.org/api/symbol/access?s={symbol}&l=en&t=pdf"
)
_USER_AGENT = "un-extractor/1.0 (research; github.com/cravesoft/un-extractor)"

# ---------------------------------------------------------------------------
# PDF fetching & text extraction
# ---------------------------------------------------------------------------


def _fetch_pdf(symbol: str, timeout: int = 30) -> bytes | None:
    """Download the PDF for *symbol*; return raw bytes or None on failure."""
    url = _API_URL.format(symbol=urllib.parse.quote(symbol, safe="/:"))
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return bytes(resp.read())
    except urllib.error.HTTPError as exc:
        log.debug("HTTP %s for %s", exc.code, symbol)
        return None
    except Exception as exc:  # noqa: BLE001
        log.debug("Error fetching %s: %s", symbol, exc)
        return None


def _extract_text(pdf_bytes: bytes) -> str:
    """Extract plain text from PDF bytes using PyMuPDF."""
    with fitz.open(stream=io.BytesIO(pdf_bytes), filetype="pdf") as doc:
        parts = [page.get_text() for page in doc]
    return "\n".join(parts).strip()


# ---------------------------------------------------------------------------
# Main import
# ---------------------------------------------------------------------------


def _fetch_pending(
    session: Session, limit: int | None
) -> list[tuple[int, str]]:
    """Return [(resolution_id, adopted_symbol), ...] with no full_text yet."""
    q = (
        "SELECT id, adopted_symbol "
        "FROM resolutions "
        "WHERE body = 'GA' "
        "  AND full_text IS NULL "
        "  AND adopted_symbol IS NOT NULL "
        "ORDER BY id"
    )
    if limit is not None:
        q += f" LIMIT {int(limit)}"
    rows = session.execute(text(q)).fetchall()
    return [(row[0], row[1]) for row in rows]


def import_ga_resolution_texts(
    db_url: str | None = None,
    limit: int | None = None,
    delay: float = 1.0,
    batch: int = 50,
    dry_run: bool = False,
    timeout: int = 30,
) -> None:
    engine = get_engine(db_url)
    create_schema(engine)

    with get_session(engine) as session:
        pending = _fetch_pending(session, limit)

    log.info(
        "Found %d GA resolutions with missing full_text%s.",
        len(pending),
        " (dry-run)" if dry_run else "",
    )
    if not pending:
        return

    fetched = failed = 0

    with get_session(engine) as session:
        for i, (res_id, symbol) in enumerate(pending):
            if i > 0 and delay > 0:
                time.sleep(delay)

            pdf_bytes = _fetch_pdf(symbol, timeout=timeout)
            if pdf_bytes is None:
                log.debug("No PDF for %s (id=%d).", symbol, res_id)
                failed += 1
                continue

            full_text = _extract_text(pdf_bytes)
            if not full_text:
                log.debug("Empty text for %s (id=%d).", symbol, res_id)
                failed += 1
                continue

            if not dry_run:
                session.execute(
                    text(
                        "UPDATE resolutions SET full_text = :txt WHERE id = :id"
                    ),
                    {"txt": full_text, "id": res_id},
                )
                session.flush()

            fetched += 1
            log.debug(
                "[%d/%d] %s → %d chars",
                i + 1,
                len(pending),
                symbol,
                len(full_text),
            )

            # Commit in batches so progress is preserved on interruption
            if not dry_run and fetched % batch == 0:
                session.commit()
                log.info(
                    "  … committed %d/%d (failed %d)",
                    fetched,
                    len(pending),
                    failed,
                )

        if not dry_run:
            session.commit()

    action = "Would store" if dry_run else "Stored"
    log.info(
        "%s full text for %d resolutions; %d had no accessible PDF.",
        action,
        fetched,
        failed,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    p = argparse.ArgumentParser(
        description="Fetch GA resolution full texts from documents.un.org.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Stop after processing N resolutions",
    )
    p.add_argument(
        "--delay",
        type=float,
        default=1.0,
        metavar="SECS",
        help="Pause between HTTP requests (rate limiting)",
    )
    p.add_argument(
        "--batch",
        type=int,
        default=50,
        metavar="N",
        help="Commit to the DB every N successful fetches",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=30,
        metavar="SECS",
        help="HTTP request timeout",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and extract text but do not write to the database",
    )
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    import_ga_resolution_texts(
        db_url=args.db,
        limit=args.limit,
        delay=args.delay,
        batch=args.batch,
        dry_run=args.dry_run,
        timeout=args.timeout,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
