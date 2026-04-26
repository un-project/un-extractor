#!/usr/bin/env python3
"""Import SC draft resolution texts and co-sponsorship from UNBench dataset.

Processes JSON files from the UNBench dataset (Liang et al., MIT license),
which provides full texts of SC draft resolutions (1994–2024) including
*rejected* drafts absent from the UNDL voting CSV.

Each JSON file has the structure::

    {
        "ID":      "S/2023/970",      # draft_symbol
        "Title":   "...",
        "Authors": "France"           # string or list of strings
        "Content": "...",             # full draft text
        "Date":    "2023-12-08"
    }

Schema changes applied automatically:

  ``resolutions.draft_text TEXT``            — full draft resolution text
  ``resolution_sponsors`` table              — (resolution_id, country_id, country_name)

For draft symbols not yet in the DB (rejected/vetoed drafts), a stub
``resolutions`` row is created with ``body='SC'`` and ``adopted_symbol=NULL``.

Data source
-----------
The full dataset (~3,000 drafts) must be downloaded manually from Google Drive
(see https://github.com/yueqingliang1/UNBench for the link) and extracted to a
local directory.  Pass that directory with ``--data-dir``.

The ``--sample`` flag downloads the 30-file GitHub subset for testing without
the full download.

Usage
-----
    # Full dataset (after manual download + extraction):
    python scripts/import_unbench_sc_drafts.py --data-dir /path/to/unbench/

    # 30-file sample from GitHub (no manual download needed):
    python scripts/import_unbench_sc_drafts.py --sample

    # Other options:
    python scripts/import_unbench_sc_drafts.py --db postgresql://...
    python scripts/import_unbench_sc_drafts.py --dry-run
    python scripts/import_unbench_sc_drafts.py --verbose

Source
------
  Liang, Y., et al. (2024). UNBench: A Comprehensive Benchmark for
  AI-Assisted United Nations Security Council Tasks.
  https://github.com/yueqingliang1/UNBench  (MIT license)
"""

from __future__ import annotations

import argparse
import ast
import json
import logging
import sys
import urllib.request
from collections.abc import Iterator
from datetime import date as _Date
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402
from src.extraction.country_aliases import normalize_country_name  # noqa: E402

log = logging.getLogger(__name__)

_CACHE_DIR = Path(__file__).resolve().parents[1] / "data" / "unbench"

# GitHub API base for sample files
_GITHUB_TASK2_API = (
    "https://api.github.com/repos/yueqingliang1/UNBench/contents/data/task2"
)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def _ensure_schema(session: Session) -> None:
    # Add draft_text column if absent
    existing_cols = {
        row[0]
        for row in session.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'resolutions'"
            )
        ).fetchall()
    }
    if "draft_text" not in existing_cols:
        session.execute(text("ALTER TABLE resolutions ADD COLUMN draft_text TEXT"))
        log.info("Added column resolutions.draft_text")

    # Create resolution_sponsors table
    session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS resolution_sponsors (
                id            SERIAL PRIMARY KEY,
                resolution_id INTEGER NOT NULL
                              REFERENCES resolutions(id) ON DELETE CASCADE,
                country_id    INTEGER REFERENCES countries(id) ON DELETE SET NULL,
                country_name  TEXT NOT NULL,
                UNIQUE (resolution_id, country_name)
            )
            """
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_res_sponsors_resolution "
            "ON resolution_sponsors (resolution_id)"
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_res_sponsors_country "
            "ON resolution_sponsors (country_id)"
        )
    )
    session.commit()
    log.info("Schema ready (draft_text, resolution_sponsors).")


# ---------------------------------------------------------------------------
# Download sample files from GitHub
# ---------------------------------------------------------------------------


def _download_samples(force: bool = False) -> Path:
    """Download the 30-file task2 sample subset from GitHub."""
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    marker = _CACHE_DIR / ".samples_downloaded"
    if marker.exists() and not force:
        log.info("Using cached sample files in %s", _CACHE_DIR)
        return _CACHE_DIR

    log.info("Fetching sample file list from GitHub …")
    req = urllib.request.Request(
        _GITHUB_TASK2_API,
        headers={"User-Agent": "un-extractor/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        dirs = json.loads(resp.read())

    n = 0
    for entry in dirs:
        if entry.get("type") != "dir":
            continue
        sub_req = urllib.request.Request(
            entry["url"],
            headers={"User-Agent": "un-extractor/1.0"},
        )
        with urllib.request.urlopen(sub_req, timeout=30) as resp:
            files = json.loads(resp.read())
        for f in files:
            if not f["name"].endswith(".json"):
                continue
            dest = _CACHE_DIR / f["name"]
            if dest.exists() and not force:
                n += 1
                continue
            dl_req = urllib.request.Request(
                f["download_url"],
                headers={"User-Agent": "un-extractor/1.0"},
            )
            with urllib.request.urlopen(dl_req, timeout=30) as resp:
                dest.write_bytes(resp.read())
            n += 1

    marker.touch()
    log.info("Downloaded %d sample JSON files to %s", n, _CACHE_DIR)
    return _CACHE_DIR


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_authors(raw: str | list[str]) -> list[str]:
    """Return a list of author strings from the Authors field.

    Handles:
      - Plain string:            "France"
      - Python list repr:        "['France', 'Germany']"
      - JSON array (already list): ["France", "Germany"]
    """
    if isinstance(raw, list):
        return [str(a).strip() for a in raw if str(a).strip()]
    s = str(raw).strip()
    if s.startswith("["):
        try:
            parsed = ast.literal_eval(s)
            if isinstance(parsed, list):
                return [str(a).strip() for a in parsed if str(a).strip()]
        except (ValueError, SyntaxError):
            pass
    return [s] if s else []


def _build_country_index(session: Session) -> dict[str, int]:
    rows = session.execute(
        text("SELECT name, id FROM countries")
    ).fetchall()
    return {name: cid for name, cid in rows}


def _resolve_country(
    raw_name: str,
    country_index: dict[str, int],
) -> int | None:
    normalised = normalize_country_name(raw_name)
    cid = country_index.get(normalised)
    if cid is None:
        cid = country_index.get(raw_name)
    return cid


def _iter_json_files(data_dir: Path) -> Iterator[tuple[Path, dict[str, Any]]]:
    """Yield all .json files recursively under data_dir."""
    for path in sorted(data_dir.rglob("*.json")):
        if path.name.startswith("."):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            log.warning("Skipping %s: %s", path, exc)
            continue
        if isinstance(data, dict) and "ID" in data and "Content" in data:
            yield path, data


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def import_unbench_sc_drafts(
    db_url: str | None = None,
    data_dir: Path | None = None,
    use_sample: bool = False,
    force_download: bool = False,
    dry_run: bool = False,
) -> None:
    if use_sample and data_dir is None:
        data_dir = _download_samples(force=force_download)
    elif data_dir is None:
        log.error("Provide --data-dir or use --sample.")
        sys.exit(1)

    engine = get_engine(db_url)
    create_schema(engine)

    with get_session(engine) as session:
        _ensure_schema(session)
        country_index = _build_country_index(session)

    inserted_res = updated_res = inserted_sponsors = 0

    with get_session(engine) as session:
        for path, data in _iter_json_files(data_dir):
            draft_symbol = (data.get("ID") or "").strip()
            if not draft_symbol:
                continue

            title = (data.get("Title") or "").strip() or None
            draft_text = (data.get("Content") or "").strip() or None
            authors_raw = data.get("Authors", "")
            authors = _parse_authors(authors_raw)

            log.debug("Processing %s (authors: %s)", draft_symbol, authors)

            # Find or create resolutions row
            row = session.execute(
                text("SELECT id, title FROM resolutions WHERE draft_symbol = :ds"),
                {"ds": draft_symbol},
            ).fetchone()

            if row is None:
                if not dry_run:
                    result = session.execute(
                        text(
                            """
                            INSERT INTO resolutions (draft_symbol, body, title, draft_text)
                            VALUES (:ds, 'SC', :title, :draft_text)
                            RETURNING id
                            """
                        ),
                        {"ds": draft_symbol, "title": title, "draft_text": draft_text},
                    )
                    res_id = result.fetchone()[0]
                else:
                    res_id = None
                inserted_res += 1
                log.debug("Created stub resolution for %s", draft_symbol)
            else:
                res_id = row[0]
                existing_title = row[1]
                if not dry_run:
                    session.execute(
                        text(
                            """
                            UPDATE resolutions SET
                                draft_text = COALESCE(draft_text, :draft_text),
                                title      = COALESCE(title, :title)
                            WHERE id = :id
                            """
                        ),
                        {"draft_text": draft_text, "title": title, "id": res_id},
                    )
                updated_res += 1

            # Insert sponsors
            if res_id is not None:
                for author_name in authors:
                    country_id = _resolve_country(author_name, country_index)
                    if not dry_run:
                        session.execute(
                            text(
                                """
                                INSERT INTO resolution_sponsors
                                    (resolution_id, country_id, country_name)
                                VALUES (:res_id, :cid, :name)
                                ON CONFLICT (resolution_id, country_name) DO NOTHING
                                """
                            ),
                            {
                                "res_id": res_id,
                                "cid": country_id,
                                "name": author_name,
                            },
                        )
                    inserted_sponsors += 1

        if not dry_run:
            session.commit()

    action = "Would create/update" if dry_run else "Created/updated"
    log.info(
        "%s %d new + %d existing resolutions; %d sponsor rows.",
        action,
        inserted_res,
        updated_res,
        inserted_sponsors,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Import SC draft resolution texts and sponsors from UNBench dataset."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument(
        "--data-dir",
        default=None,
        metavar="PATH",
        help="Directory containing UNBench JSON files (full dataset, manually downloaded)",
    )
    p.add_argument(
        "--sample",
        action="store_true",
        help="Download and use the 30-file GitHub sample subset instead of full dataset",
    )
    p.add_argument(
        "--download",
        action="store_true",
        help="Force re-download of sample files (only with --sample)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and log without writing to the database",
    )
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    if not args.data_dir and not args.sample:
        p.error("Provide --data-dir PATH or --sample (30-file GitHub subset).")

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    import_unbench_sc_drafts(
        db_url=args.db,
        data_dir=Path(args.data_dir) if args.data_dir else None,
        use_sample=args.sample,
        force_download=args.download,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
