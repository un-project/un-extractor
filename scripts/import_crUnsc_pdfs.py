#!/usr/bin/env python3
"""Place CR-UNSC meeting-record PDFs into the pipeline input directory.

Downloads ``EN_PDF_Meeting-Records.zip`` (~2.1 GB) from the CR-UNSC Zenodo
release and moves each PDF to its canonical location under
``data/raw_pdfs/en/sc/{year}/pv/document_{N}.pdf`` so that
``process_dataset.py`` can pick them up.

Meeting record filenames in the zip follow the pattern:
    S-PV-NNNN_YEAR-MM-DD.pdf   →   data/raw_pdfs/en/sc/{YEAR}/pv/document_{NNNN}.pdf

Files that already exist at the destination are not overwritten unless
``--overwrite`` is specified.  The script is safe to re-run.

CR-UNSC dataset
---------------
  Fobbe, S. (2025). CR-UNSC: Compilation of Resolutions of the United
  Nations Security Council. Zenodo. https://doi.org/10.5281/zenodo.7319780

Usage
-----
    python scripts/import_crUnsc_pdfs.py
    python scripts/import_crUnsc_pdfs.py --zip path/to/EN_PDF_Meeting-Records.zip
    python scripts/import_crUnsc_pdfs.py --download
    python scripts/import_crUnsc_pdfs.py --overwrite
    python scripts/import_crUnsc_pdfs.py --dry-run
    python scripts/import_crUnsc_pdfs.py --verbose
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Zenodo download URL (update when a new version is published)
# ---------------------------------------------------------------------------

_PDF_ZIP_URL = (
    "https://zenodo.org/api/records/15154519/files"
    "/CR-UNSC_2025-12-22_EN_PDF_Meeting-Records.zip/content"
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DATA_DIR = _REPO_ROOT / "data" / "crUnsc"
_OUTPUT_ROOT = _REPO_ROOT / "data" / "raw_pdfs" / "en" / "sc"

# ---------------------------------------------------------------------------
# Filename pattern
# ---------------------------------------------------------------------------

# CR-UNSC naming convention examples:
#   S-PV-3756_1997-01-15.pdf
#   S-PV-10100_2026-01-12.pdf
# We capture: meeting_number (N) and year from the date field.
_FNAME_RE = re.compile(
    r"S-PV-(\d+)[_-](\d{4})-\d{2}-\d{2}\.pdf$",
    re.IGNORECASE,
)


def _dest_path(meeting_number: int, year: int) -> Path:
    return _OUTPUT_ROOT / str(year) / "pv" / f"document_{meeting_number}.pdf"


# ---------------------------------------------------------------------------
# Download helper (with progress reporting for large files)
# ---------------------------------------------------------------------------


def _download(url: str, dest: Path, force: bool = False) -> Path:
    if dest.exists() and not force:
        log.info("Using cached %s (%.1f MB)", dest.name, dest.stat().st_size / 1e6)
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    log.info("Downloading %s …", url)
    log.info("This file is ~2.1 GB and may take several minutes.")

    def _progress(block_count: int, block_size: int, total_size: int) -> None:
        downloaded = block_count * block_size
        if total_size > 0 and downloaded % (50 * 1024 * 1024) < block_size:
            pct = min(100, downloaded * 100 // total_size)
            log.info("  … %d%% (%.0f MB / %.0f MB)", pct, downloaded / 1e6, total_size / 1e6)

    urllib.request.urlretrieve(url, dest, reporthook=_progress)
    log.info("Downloaded %s (%.1f MB)", dest.name, dest.stat().st_size / 1e6)
    return dest


# ---------------------------------------------------------------------------
# Main extraction logic
# ---------------------------------------------------------------------------


def _place_pdfs(
    zip_path: Path,
    output_root: Path,
    overwrite: bool,
    dry_run: bool,
) -> tuple[int, int, int]:
    """Extract PDFs from the zip to the canonical directory layout.

    Returns (placed, skipped_existing, unrecognised).
    """
    placed = skipped_existing = unrecognised = 0

    with zipfile.ZipFile(zip_path) as zf:
        pdf_names = [n for n in zf.namelist() if n.lower().endswith(".pdf")]
        log.info("Found %d PDF entries in zip.", len(pdf_names))

        for entry in pdf_names:
            fname = Path(entry).name
            m = _FNAME_RE.match(fname)
            if not m:
                log.debug("Unrecognised filename pattern: %s", fname)
                unrecognised += 1
                continue

            meeting_number = int(m.group(1))
            year = int(m.group(2))
            dest = _dest_path(meeting_number, year)

            if dest.exists() and not overwrite:
                log.debug("Already exists, skipping: %s", dest)
                skipped_existing += 1
                continue

            log.info("PLACE  %s  →  %s", fname, dest.relative_to(_REPO_ROOT))
            if not dry_run:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(entry))
            placed += 1

    return placed, skipped_existing, unrecognised


def import_crUnsc_pdfs(
    zip_path: Path | None = None,
    output_root: Path | None = None,
    download: bool = False,
    overwrite: bool = False,
    dry_run: bool = False,
) -> None:
    if output_root is None:
        output_root = _OUTPUT_ROOT

    if zip_path is None:
        zip_path = _DATA_DIR / "CR-UNSC_2025-12-22_EN_PDF_Meeting-Records.zip"

    _download(_PDF_ZIP_URL, zip_path, force=download)

    placed, skipped, unrecognised = _place_pdfs(zip_path, output_root, overwrite, dry_run)

    action = "Would place" if dry_run else "Placed"
    log.info(
        "%s %d PDFs (skipped %d existing, %d unrecognised filenames).",
        action,
        placed,
        skipped,
        unrecognised,
    )
    if placed > 0 and not dry_run:
        log.info(
            "Next step: run process_dataset.py on %s to extract meeting records.",
            output_root,
        )


def main() -> int:
    p = argparse.ArgumentParser(
        description="Place CR-UNSC meeting-record PDFs into the pipeline input directory.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--zip",
        default=None,
        help="Path to EN_PDF_Meeting-Records.zip (local file; downloads if absent)",
    )
    p.add_argument(
        "--output-root",
        default=None,
        help=f"Root directory for SC PDFs (default: {_OUTPUT_ROOT})",
    )
    p.add_argument(
        "--download",
        action="store_true",
        help="Force re-download even if cached file exists",
    )
    p.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite PDFs that already exist at the destination",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be placed without writing any files",
    )
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    import_crUnsc_pdfs(
        zip_path=Path(args.zip) if args.zip else None,
        output_root=Path(args.output_root) if args.output_root else None,
        download=args.download,
        overwrite=args.overwrite,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
