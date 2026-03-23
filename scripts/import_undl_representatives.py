#!/usr/bin/env python3
"""Import UN Permanent Representatives and SC Representatives into the database.

Downloads two DHL datasets and populates:
  - ``permanent_representatives`` — historical/current UN ambassadors
  - ``sc_representatives``        — SC member state reps and SC presidents

For each person, the script attempts to match an existing ``speakers`` row
by last-name + country, storing the FK in ``speaker_id``.

Sources
-------
  Permanent Representatives (2026-01-06):
    https://digitallibrary.un.org/record/4091498
  SC Representatives (2025-06-16):
    https://digitallibrary.un.org/record/4047618

CSV columns
-----------
  Perm Reps: undl_id, name, member_state, salutation,
             alternative_names, notes, undl_link
  SC Reps:   undl_id, name, states, salutations,
             alternative_names, sc_president, notes, undl_link

Usage
-----
    python scripts/import_undl_representatives.py
    python scripts/import_undl_representatives.py --db postgresql://...
    python scripts/import_undl_representatives.py --skip-perm-reps
    python scripts/import_undl_representatives.py --skip-sc-reps
    python scripts/import_undl_representatives.py --dry-run
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.db.database import create_schema, get_engine, get_session  # noqa: E402
from src.db.models import (  # noqa: E402
    Country,
    PermanentRepresentative,
    SCRepresentative,
    Speaker,
)
from src.extraction.country_aliases import normalize_country_name  # noqa: E402

log = logging.getLogger(__name__)

_PERM_REPS_URL = (
    "https://digitallibrary.un.org/record/4091498/files"
    "/2026_01_06_ambassadors.csv"
)
_SC_REPS_URL = (
    "https://digitallibrary.un.org/record/4047618/files"
    "/2025_06_16_sc_representatives.csv"
)
_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "undl"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _download(url: str, dest: Path, force: bool = False) -> Path:
    if dest.exists() and not force:
        log.info("Using cached %s", dest)
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    log.info("Downloading %s …", url)
    urllib.request.urlretrieve(url, dest)
    log.info("Downloaded %s", dest.name)
    return dest


def _normalise_name(raw: str) -> str:
    """'Last, First' → 'First Last'."""
    if "," in raw:
        last, _, first = raw.partition(",")
        return f"{first.strip()} {last.strip()}"
    return raw.strip()


def _build_country_index(session) -> dict[str, int]:
    rows = session.query(Country.id, Country.name).all()
    return {normalize_country_name(name): cid for cid, name in rows}


def _find_speaker(session, display_name: str, country_id: int | None) -> int | None:
    if not country_id:
        return None
    last = display_name.split()[-1] if display_name else ""
    if not last:
        return None
    spk = (
        session.query(Speaker)
        .filter_by(country_id=country_id)
        .filter(Speaker.name.ilike(f"%{last}%"))
        .first()
    )
    return spk.id if spk else None


# ---------------------------------------------------------------------------
# Permanent Representatives
# ---------------------------------------------------------------------------


def _import_perm_reps(
    session, csv_path: Path, country_idx: dict[str, int], dry_run: bool
) -> tuple[int, int]:
    inserted = skipped = 0

    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            undl_id = (row.get("undl_id") or "").strip() or None
            raw_name = (row.get("name") or "").strip()
            member_state = (row.get("member_state") or "").strip()
            salutation = (row.get("salutation") or "").strip() or None
            notes = (row.get("notes") or "").strip() or None
            undl_link = (row.get("undl_link") or "").strip() or None

            if not raw_name:
                skipped += 1
                continue

            display_name = _normalise_name(raw_name)
            country_id = country_idx.get(normalize_country_name(member_state))
            speaker_id = _find_speaker(session, display_name, country_id)

            # Skip if already imported
            if undl_id:
                exists = (
                    session.query(PermanentRepresentative)
                    .filter_by(undl_id=undl_id)
                    .first()
                )
                if exists:
                    log.debug("Already imported perm rep undl_id=%s", undl_id)
                    continue

            log.debug("INSERT perm rep  %r  country=%s", display_name, member_state)
            if not dry_run:
                pr = PermanentRepresentative(
                    country_id=country_id,
                    speaker_id=speaker_id,
                    name=display_name,
                    salutation=salutation,
                    notes=notes,
                    undl_id=undl_id,
                    undl_link=undl_link,
                )
                session.add(pr)
                session.flush()
            inserted += 1

    return inserted, skipped


# ---------------------------------------------------------------------------
# SC Representatives
# ---------------------------------------------------------------------------


def _import_sc_reps(
    session, csv_path: Path, country_idx: dict[str, int], dry_run: bool
) -> tuple[int, int]:
    inserted = skipped = 0

    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            undl_id = (row.get("undl_id") or "").strip() or None
            raw_name = (row.get("name") or "").strip()
            # SC CSV uses "states" (may list multiple, semicolon-separated)
            states_raw = (row.get("states") or "").strip()
            salutation = (row.get("salutations") or "").strip() or None
            sc_pres_raw = (row.get("sc_president") or "").strip().upper()
            sc_president = True if sc_pres_raw == "TRUE" else (
                False if sc_pres_raw == "FALSE" else None
            )
            notes = (row.get("notes") or "").strip() or None
            undl_link = (row.get("undl_link") or "").strip() or None

            if not raw_name:
                skipped += 1
                continue

            display_name = _normalise_name(raw_name)

            # Use first listed state for country matching
            primary_state = states_raw.split(";")[0].strip()
            country_id = country_idx.get(normalize_country_name(primary_state))
            speaker_id = _find_speaker(session, display_name, country_id)

            if undl_id:
                exists = (
                    session.query(SCRepresentative)
                    .filter_by(undl_id=undl_id)
                    .first()
                )
                if exists:
                    log.debug("Already imported SC rep undl_id=%s", undl_id)
                    continue

            log.debug(
                "INSERT SC rep  %r  country=%s  president=%s",
                display_name, primary_state, sc_president,
            )
            if not dry_run:
                sr = SCRepresentative(
                    country_id=country_id,
                    speaker_id=speaker_id,
                    name=display_name,
                    salutation=salutation,
                    sc_president=sc_president,
                    notes=notes,
                    undl_id=undl_id,
                    undl_link=undl_link,
                )
                session.add(sr)
                session.flush()
            inserted += 1

    return inserted, skipped


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def import_undl_representatives(
    db_url: str | None = None,
    perm_reps_csv: Path | None = None,
    sc_reps_csv: Path | None = None,
    skip_perm_reps: bool = False,
    skip_sc_reps: bool = False,
    download: bool = False,
    dry_run: bool = False,
) -> None:
    engine = get_engine(db_url)
    create_schema(engine)  # creates new tables from models

    if not skip_perm_reps:
        if perm_reps_csv is None:
            perm_reps_csv = _DATA_DIR / "2026_01_06_ambassadors.csv"
        _download(_PERM_REPS_URL, perm_reps_csv, force=download)

    if not skip_sc_reps:
        if sc_reps_csv is None:
            sc_reps_csv = _DATA_DIR / "2025_06_16_sc_representatives.csv"
        _download(_SC_REPS_URL, sc_reps_csv, force=download)

    with get_session(engine) as session:
        country_idx = _build_country_index(session)

        if not skip_perm_reps:
            pr_ins, pr_skip = _import_perm_reps(session, perm_reps_csv, country_idx, dry_run)
            action = "Would insert" if dry_run else "Inserted"
            log.info("%s %d permanent representatives (%d skipped).", action, pr_ins, pr_skip)

        if not skip_sc_reps:
            sc_ins, sc_skip = _import_sc_reps(session, sc_reps_csv, country_idx, dry_run)
            action = "Would insert" if dry_run else "Inserted"
            log.info("%s %d SC representatives (%d skipped).", action, sc_ins, sc_skip)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Import UN Permanent and SC Representatives into the database.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None)
    p.add_argument("--perm-reps-csv", default=None)
    p.add_argument("--sc-reps-csv", default=None)
    p.add_argument("--skip-perm-reps", action="store_true")
    p.add_argument("--skip-sc-reps", action="store_true")
    p.add_argument("--download", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )
    import_undl_representatives(
        db_url=args.db,
        perm_reps_csv=Path(args.perm_reps_csv) if args.perm_reps_csv else None,
        sc_reps_csv=Path(args.sc_reps_csv) if args.sc_reps_csv else None,
        skip_perm_reps=args.skip_perm_reps,
        skip_sc_reps=args.skip_sc_reps,
        download=args.download,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
