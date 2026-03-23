#!/usr/bin/env python3
"""Import GA resolution metadata from the DHL GA Outcomes dataset.

Downloads the authoritative GA resolutions CSV (20,761 entries, 1946–2025)
and upserts title, subjects, agenda_title, committee_report, vote totals,
undl_id, and undl_link into the ``resolutions`` table.

This complements ``import_undl_votes.py``, which only contains rows for
resolutions adopted through a recorded vote.  The GA Outcomes CSV covers
ALL adopted resolutions including consensus ones, filling gaps in metadata.

Source
------
  Dag Hammarskjöld Library (2026). UN General Assembly Resolutions (v5).
  https://digitallibrary.un.org/record/4060945

CSV columns
-----------
  undl_id, resolution, session, date, title, modality, draft,
  committee_report, meeting, agenda_title, subjects, vote_note,
  total_yes, total_no, total_abstentions, total_non_voting, total_ms,
  undl_link

Usage
-----
    python scripts/import_undl_ga_resolutions.py
    python scripts/import_undl_ga_resolutions.py --db postgresql://...
    python scripts/import_undl_ga_resolutions.py --dry-run
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402
from src.db.models import Resolution  # noqa: E402
from src.extraction.vote_categories import classify_subjects  # noqa: E402

log = logging.getLogger(__name__)

_CSV_URL = (
    "https://digitallibrary.un.org/record/4060945/files"
    "/2026_02_06_ga_outcomes.csv"
)
_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "undl"


# ---------------------------------------------------------------------------
# Schema migration
# ---------------------------------------------------------------------------


def _ensure_columns(session) -> None:
    for col, typ in [
        ("undl_id", "VARCHAR(30)"),
        ("undl_link", "VARCHAR(500)"),
    ]:
        exists = session.execute(
            text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name='resolutions' AND column_name=:c"
            ),
            {"c": col},
        ).fetchone()
        if exists is None:
            log.info("Adding column resolutions.%s …", col)
            session.execute(
                text(f"ALTER TABLE resolutions ADD COLUMN IF NOT EXISTS {col} {typ}")
            )
    session.commit()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _int_or_none(s: str) -> int | None:
    try:
        return int(s) if s and s.strip() else None
    except ValueError:
        return None


def _download(url: str, dest: Path, force: bool = False) -> Path:
    if dest.exists() and not force:
        log.info("Using cached %s", dest)
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    log.info("Downloading %s …", url)
    urllib.request.urlretrieve(url, dest)
    log.info("Downloaded %s (%.1f MB)", dest.name, dest.stat().st_size / 1e6)
    return dest


# ---------------------------------------------------------------------------
# Main import
# ---------------------------------------------------------------------------


def _import(session, csv_path: Path, dry_run: bool) -> tuple[int, int, int]:
    updated = inserted_stub = skipped = 0

    # Build adopted_symbol → resolution id index
    rows = session.query(Resolution.id, Resolution.adopted_symbol).filter(
        Resolution.body == "GA"
    ).all()
    sym_idx: dict[str, int] = {}
    for rid, sym in rows:
        if sym:
            sym_idx[sym] = rid
            # Also index without trailing spaces / case variants
            sym_idx[sym.strip()] = rid

    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            resolution_sym = (row.get("resolution") or "").strip()
            undl_id = (row.get("undl_id") or "").strip() or None
            title = (row.get("title") or "").strip() or None
            subjects = (row.get("subjects") or "").strip() or None
            agenda_title = (row.get("agenda_title") or "").strip() or None
            committee_report = (row.get("committee_report") or "").strip() or None
            vote_note = (row.get("vote_note") or "").strip() or None
            undl_link = (row.get("undl_link") or "").strip() or None
            draft = (row.get("draft") or "").strip() or None

            yes = _int_or_none(row.get("total_yes", ""))
            no = _int_or_none(row.get("total_no", ""))
            abstain = _int_or_none(row.get("total_abstentions", ""))
            non_voting = _int_or_none(row.get("total_non_voting", ""))
            total_ms = _int_or_none(row.get("total_ms", ""))

            category = classify_subjects(subjects) if subjects else None

            res_id = sym_idx.get(resolution_sym)
            if res_id is None:
                log.debug("No resolution row for %r — skipping.", resolution_sym)
                skipped += 1
                continue

            res = session.query(Resolution).get(res_id)
            log.debug("UPDATE resolution id=%d  %s", res_id, resolution_sym)

            if not dry_run:
                if title and not res.title:
                    res.title = title
                if subjects and not res.category:
                    res.category = category or subjects[:200]
                if agenda_title and not res.agenda_title:
                    res.agenda_title = agenda_title
                if committee_report and not res.committee_report:
                    res.committee_report = committee_report
                if undl_id and not res.undl_id:
                    res.undl_id = undl_id
                if undl_link and not res.undl_link:
                    res.undl_link = undl_link
                if draft and not res.draft_symbol:
                    res.draft_symbol = draft
                session.flush()

            updated += 1

    return updated, inserted_stub, skipped


def import_undl_ga_resolutions(
    db_url: str | None = None,
    csv_path: Path | None = None,
    download: bool = False,
    dry_run: bool = False,
) -> None:
    engine = get_engine(db_url)
    create_schema(engine)

    with get_session(engine) as session:
        _ensure_columns(session)

    if csv_path is None:
        csv_path = _DATA_DIR / "2026_02_06_ga_outcomes.csv"

    _download(_CSV_URL, csv_path, force=download)

    with get_session(engine) as session:
        updated, _, skipped = _import(session, csv_path, dry_run)

    action = "Would update" if dry_run else "Updated"
    log.info("%s %d resolution rows (%d not in DB).", action, updated, skipped)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Import GA resolution metadata from DHL GA Outcomes dataset.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None)
    p.add_argument("--csv", default=None)
    p.add_argument("--download", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )
    import_undl_ga_resolutions(
        db_url=args.db,
        csv_path=Path(args.csv) if args.csv else None,
        download=args.download,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
