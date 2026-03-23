#!/usr/bin/env python3
"""Import CR-UNSC resolution full texts into the database.

Downloads ``EN_TXT_BEST.zip`` from the CR-UNSC Zenodo release, extracts
plain-text resolution files, and upserts ``full_text`` and ``crUnsc_id``
into the ``resolutions`` table.

Each text file is named like ``S-RES-0001E.txt`` (or similar).  The script
derives the canonical UNDL adopted symbol (e.g. ``S/RES/1(1946)``) from the
filename, looks up the matching resolution row, and writes the full text.

CR-UNSC dataset
---------------
  Fobbe, S. (2025). CR-UNSC: Compilation of Resolutions of the United
  Nations Security Council. Zenodo. https://doi.org/10.5281/zenodo.7319780

Usage
-----
    python scripts/import_crUnsc_texts.py
    python scripts/import_crUnsc_texts.py --db postgresql://user:pass@host/db
    python scripts/import_crUnsc_texts.py --zip path/to/EN_TXT_BEST.zip
    python scripts/import_crUnsc_texts.py --download
    python scripts/import_crUnsc_texts.py --dry-run
    python scripts/import_crUnsc_texts.py --verbose
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402
from src.db.models import Resolution  # noqa: E402

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Zenodo download URL (update when a new version is published)
# ---------------------------------------------------------------------------

_TXT_ZIP_URL = (
    "https://zenodo.org/api/records/15154519/files"
    "/CR-UNSC_2025-12-22_EN_TXT_BEST.zip/content"
)

_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "crUnsc"

# ---------------------------------------------------------------------------
# Filename → resolution symbol mapping
# ---------------------------------------------------------------------------

# CR-UNSC text files are named like:
#   S_RES_0001_1946_EN_GOLD.txt  →  S/RES/1(1946)
#   S_RES_0242_1967_EN_GOLD.txt  →  S/RES/242(1967)
_FNAME_RE = re.compile(r"S_RES_(\d+)_(\d{4})_", re.IGNORECASE)


def _symbol_from_filename(fname: str) -> tuple[str, str] | None:
    """Return (full_symbol, crUnsc_id) derived from a CR-UNSC text filename.

    full_symbol  e.g. ``S/RES/1(1946)``  — matches UNDL adopted_symbol exactly
    crUnsc_id    e.g. ``S_RES_0001_1946_EN_GOLD``  — the filename stem
    """
    m = _FNAME_RE.search(Path(fname).name)
    if not m:
        return None
    number = int(m.group(1))   # strip leading zeros
    year = m.group(2)
    full_symbol = f"S/RES/{number}({year})"
    crUnsc_id = Path(fname).stem.upper()
    return full_symbol, crUnsc_id


def _find_resolution(session: Session, full_symbol: str) -> Resolution | None:
    """Look up a resolution by its UNDL adopted_symbol (e.g. ``S/RES/1(1946)``)."""
    return (
        session.query(Resolution)
        .filter(Resolution.adopted_symbol == full_symbol)
        .first()
    )


# ---------------------------------------------------------------------------
# Schema migration
# ---------------------------------------------------------------------------


def _ensure_columns(session: Session) -> None:
    """Add full_text and crUnsc_id to resolutions if missing."""
    for column, col_type in [
        ("full_text", "TEXT"),
        ("crunsc_id", "VARCHAR(30)"),
    ]:
        exists = session.execute(
            text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name = 'resolutions' AND column_name = :c"
            ),
            {"c": column},
        ).fetchone()
        if exists is None:
            log.info("Adding column resolutions.%s …", column)
            session.execute(
                text(f"ALTER TABLE resolutions ADD COLUMN IF NOT EXISTS {column} {col_type}")
            )
    # Add unique index on crUnsc_id (WHERE NOT NULL) if missing
    idx_exists = session.execute(
        text(
            "SELECT 1 FROM pg_indexes "
            "WHERE tablename = 'resolutions' AND indexname = 'ix_res_crunsc_id'"
        )
    ).fetchone()
    if idx_exists is None:
        log.info("Creating unique index ix_res_crunsc_id …")
        session.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_res_crunsc_id "
                "ON resolutions (crunsc_id) WHERE crunsc_id IS NOT NULL"
            )
        )
    session.commit()


# ---------------------------------------------------------------------------
# Download helper
# ---------------------------------------------------------------------------


def _download(url: str, dest: Path, force: bool = False) -> Path:
    if dest.exists() and not force:
        log.info("Using cached %s", dest)
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    log.info("Downloading %s → %s …", url, dest)
    urllib.request.urlretrieve(url, dest)
    log.info("Downloaded %s (%.1f MB)", dest.name, dest.stat().st_size / 1e6)
    return dest


# ---------------------------------------------------------------------------
# Main import logic
# ---------------------------------------------------------------------------


def _import_texts(
    session: Session,
    zip_path: Path,
    dry_run: bool,
) -> tuple[int, int, int]:
    """Iterate text files in the zip and upsert into the DB.

    Returns (processed, updated, skipped).
    """
    processed = updated = skipped = 0

    with zipfile.ZipFile(zip_path) as zf:
        names = [n for n in zf.namelist() if _FNAME_RE.search(Path(n).name)]
        log.info("Found %d resolution text files in zip.", len(names))

        for entry in names:
            parsed = _symbol_from_filename(entry)
            if parsed is None:
                log.debug("Skipping unrecognised filename: %s", entry)
                skipped += 1
                continue

            full_symbol, crUnsc_id = parsed
            res = _find_resolution(session, full_symbol)
            if res is None:
                log.debug("No resolution row for %s — skipping.", full_symbol)
                skipped += 1
                continue

            full_text = zf.read(entry).decode("utf-8", errors="replace")

            log.info(
                "UPDATE resolutions id=%d  %s  crUnsc_id=%s  text_len=%d",
                res.id,
                full_symbol,
                crUnsc_id,
                len(full_text),
            )
            if not dry_run:
                res.full_text = full_text
                res.crunsc_id = crUnsc_id
                session.flush()

            processed += 1
            updated += 1

    return processed, updated, skipped


def import_crUnsc_texts(
    db_url: str | None = None,
    zip_path: Path | None = None,
    download: bool = False,
    dry_run: bool = False,
) -> None:
    engine = get_engine(db_url)
    create_schema(engine)

    with get_session(engine) as session:
        _ensure_columns(session)

    if zip_path is None:
        zip_path = _DATA_DIR / "CR-UNSC_2025-12-22_EN_TXT_BEST.zip"

    _download(_TXT_ZIP_URL, zip_path, force=download)

    with get_session(engine) as session:
        processed, updated, skipped = _import_texts(session, zip_path, dry_run)

    action = "Would update" if dry_run else "Updated"
    log.info(
        "%s %d resolution rows with full text (%d skipped).",
        action,
        updated,
        skipped,
    )


def main() -> int:
    p = argparse.ArgumentParser(
        description="Import CR-UNSC resolution texts into the database.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument("--zip", default=None, help="Path to EN_TXT_BEST.zip (local file)")
    p.add_argument(
        "--download",
        action="store_true",
        help="Force re-download even if cached file exists",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and log without writing to the database",
    )
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    import_crUnsc_texts(
        db_url=args.db,
        zip_path=Path(args.zip) if args.zip else None,
        download=args.download,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
