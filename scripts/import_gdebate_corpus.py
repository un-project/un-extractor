#!/usr/bin/env python3
"""Import UN General Debate Corpus (Baturo et al.) speech texts.

Downloads the UNGDC tar.gz from Harvard Dataverse and populates the ``text``
column of ``general_debate_entries`` rows already inserted by
``import_undl_general_debate.py``.

The corpus contains one plain-text file per speech, named::

    {ISO3}_{session}_{year}.txt   e.g.  USA_75_2020.txt

Matching key: ``(ga_session, country.iso3)`` → ``general_debate_entries.id``.

Data source
-----------
  Jankin, S., Baturo, A., & Dasandi, N. (2025).
  Words to unite nations: The complete United Nations General Debate Corpus,
  1946–present. Journal of Peace Research, 62(4), 1339-1351.
  https://doi.org/10.7910/DVN/0TJX8Y

Coverage
--------
  Sessions 1–80 (1946–2025); 11,141 speeches in plain text (UTF-8).

Usage
-----
    python scripts/import_gdebate_corpus.py
    python scripts/import_gdebate_corpus.py --db postgresql://...
    python scripts/import_gdebate_corpus.py --tarball path/to/corpus.tar.gz
    python scripts/import_gdebate_corpus.py --download     # force re-download
    python scripts/import_gdebate_corpus.py --dry-run
    python scripts/import_gdebate_corpus.py --session 75  # single session
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
import tarfile
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402

log = logging.getLogger(__name__)

# Harvard Dataverse direct-download URL for the corpus tar.gz (file id 13591895)
_CORPUS_URL = (
    "https://dataverse.harvard.edu/api/access/datafile/13591895"
)
_TARBALL_NAME = "UNGDC_1946-2025.tar.gz"
_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "undl"

# Filename pattern inside the tarball: ISO3_session_year.txt
_FNAME_RE = re.compile(r"^([A-Z]{3})_(\d{1,3})_(\d{4})\.txt$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Schema migration
# ---------------------------------------------------------------------------


def _ensure_schema(session: Session) -> None:
    """Add text column to general_debate_entries if missing."""
    exists = session.execute(
        text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = 'general_debate_entries' "
            "AND column_name = 'text'"
        )
    ).fetchone()
    if exists is None:
        log.info("Adding column general_debate_entries.text …")
        session.execute(
            text(
                "ALTER TABLE general_debate_entries "
                "ADD COLUMN IF NOT EXISTS text TEXT"
            )
        )
    session.commit()


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


def _download(url: str, dest: Path, force: bool = False) -> Path:
    if dest.exists() and not force:
        log.info("Using cached %s (%.1f MB)", dest.name, dest.stat().st_size / 1e6)
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    log.info("Downloading corpus (~68 MB) from Harvard Dataverse …")
    req = urllib.request.Request(url, headers={"User-Agent": "un-extractor/1.0"})
    with urllib.request.urlopen(req) as resp, dest.open("wb") as fh:
        while chunk := resp.read(65536):
            fh.write(chunk)
    log.info("Downloaded %s (%.1f MB)", dest.name, dest.stat().st_size / 1e6)
    return dest


# ---------------------------------------------------------------------------
# Index building
# ---------------------------------------------------------------------------


def _build_index(session: Session) -> dict[tuple[int, str], int]:
    """Return {(ga_session, iso3_upper): general_debate_entries.id}."""
    rows = session.execute(
        text(
            "SELECT gde.id, gde.ga_session, c.iso3 "
            "FROM general_debate_entries gde "
            "JOIN countries c ON c.id = gde.country_id "
            "WHERE c.iso3 IS NOT NULL"
        )
    ).fetchall()
    return {(ga_session, iso3.upper()): gde_id for gde_id, ga_session, iso3 in rows}


# ---------------------------------------------------------------------------
# Main import
# ---------------------------------------------------------------------------


def _import_corpus(
    session: Session,
    tarball: Path,
    dry_run: bool,
    only_session: int | None,
) -> tuple[int, int, int]:
    """Stream through the tarball and update matching GDE rows.

    Returns (updated, skipped_no_match, skipped_already_has_text).
    """
    gde_index = _build_index(session)
    log.info("GDE index: %d entries with iso3.", len(gde_index))

    updated = no_match = already_has = 0

    with tarfile.open(tarball, "r:gz") as tf:
        for member in tf:
            if not member.isfile():
                continue
            fname = Path(member.name).name
            m = _FNAME_RE.match(fname)
            if not m:
                continue
            iso3, sess_str = m.group(1), m.group(2)
            ga_session = int(sess_str)

            if only_session is not None and ga_session != only_session:
                continue

            key = (ga_session, iso3.upper())
            gde_id = gde_index.get(key)
            if gde_id is None:
                log.debug("No GDE entry for %s session %d.", iso3, ga_session)
                no_match += 1
                continue

            if not dry_run:
                # Check if already populated
                existing = session.execute(
                    text(
                        "SELECT text IS NOT NULL FROM general_debate_entries "
                        "WHERE id = :id"
                    ),
                    {"id": gde_id},
                ).scalar()
                if existing:
                    already_has += 1
                    continue

                fh = tf.extractfile(member)
                if fh is None:
                    continue
                speech_text = fh.read().decode("utf-8", errors="replace").strip()

                session.execute(
                    text(
                        "UPDATE general_debate_entries SET text = :txt "
                        "WHERE id = :id"
                    ),
                    {"txt": speech_text, "id": gde_id},
                )
                session.flush()

            updated += 1
            if updated % 500 == 0:
                log.info("  … %d updated so far.", updated)

    return updated, no_match, already_has


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def import_gdebate_corpus(
    db_url: str | None = None,
    tarball: Path | None = None,
    download: bool = False,
    dry_run: bool = False,
    only_session: int | None = None,
) -> None:
    engine = get_engine(db_url)
    create_schema(engine)

    with get_session(engine) as session:
        _ensure_schema(session)

    if tarball is None:
        tarball = _DATA_DIR / _TARBALL_NAME

    _download(_CORPUS_URL, tarball, force=download)

    with get_session(engine) as session:
        updated, no_match, already_has = _import_corpus(
            session, tarball, dry_run, only_session
        )

    action = "Would update" if dry_run else "Updated"
    log.info(
        "%s %d GDE rows with speech text; "
        "%d no matching GDE entry; %d already had text.",
        action,
        updated,
        no_match,
        already_has,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Import UN General Debate Corpus speech texts "
            "into general_debate_entries.text."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument("--tarball", default=None, help="Local path to corpus tar.gz")
    p.add_argument(
        "--download",
        action="store_true",
        help="Force re-download even if cached tarball exists",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Report matches without writing to the database",
    )
    p.add_argument(
        "--session",
        type=int,
        default=None,
        metavar="N",
        help="Import only this GA session number",
    )
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    import_gdebate_corpus(
        db_url=args.db,
        tarball=Path(args.tarball) if args.tarball else None,
        download=args.download,
        dry_run=args.dry_run,
        only_session=args.session,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
