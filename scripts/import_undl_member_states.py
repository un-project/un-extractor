#!/usr/bin/env python3
"""Enrich the countries table from the DHL UN Member States dataset.

For each row in the CSV:
- Sets m49, un_member_since, un_member_end on the matching country row.
- Adds Other Names and Earlier/Later Names to country_aliases.py if absent
  (logged only — alias file must be updated manually).

Source
------
  Dag Hammarskjöld Library (2025). UN Member States (2025-12-02).
  https://digitallibrary.un.org/record/4082085

CSV columns
-----------
  (index), Member State, M49 Code, ISO Code, Start date, End date,
  Other Names, Earlier or Later Name, Earlier (a) or Later (b),
  Geographic Term, Membership Document Symbol, Scope Note,
  French, Spanish, Arabic, Chinese, Russian

Usage
-----
    python scripts/import_undl_member_states.py
    python scripts/import_undl_member_states.py --db postgresql://...
    python scripts/import_undl_member_states.py --dry-run
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
import urllib.request
from datetime import date, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402
from src.db.models import Country  # noqa: E402
from src.extraction.country_aliases import normalize_country_name  # noqa: E402

log = logging.getLogger(__name__)

_CSV_URL = (
    "https://digitallibrary.un.org/record/4082085/files"
    "/member_states_auths_2025-12-02_rev-1.csv"
)
_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "undl"


# ---------------------------------------------------------------------------
# Schema migration
# ---------------------------------------------------------------------------


def _ensure_columns(session) -> None:
    for col, typ in [("m49", "VARCHAR(5)"), ("un_member_end", "DATE")]:
        exists = session.execute(
            text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name='countries' AND column_name=:c"
            ),
            {"c": col},
        ).fetchone()
        if exists is None:
            log.info("Adding column countries.%s …", col)
            session.execute(
                text(f"ALTER TABLE countries ADD COLUMN IF NOT EXISTS {col} {typ}")
            )
    session.commit()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_date(s: str) -> date | None:
    if not s or not s.strip():
        return None
    s = s.strip()
    for fmt in ("%m/%d/%y", "%m/%d/%Y", "%Y-%m-%d"):
        try:
            d = datetime.strptime(s, fmt).date()
            # Two-digit year: Python maps 00-68 → 2000-2068; fix future dates
            if d.year > date.today().year:
                d = d.replace(year=d.year - 100)
            return d
        except ValueError:
            continue
    log.debug("Could not parse date %r", s)
    return None


def _build_country_index(session) -> dict[str, int]:
    rows = session.query(Country.id, Country.name, Country.iso3).all()
    idx: dict[str, int] = {}
    for cid, name, iso3 in rows:
        idx[normalize_country_name(name)] = cid
        if iso3:
            idx[iso3] = cid
    return idx


def _find_country(idx: dict[str, int], member_state: str, iso_code: str) -> int | None:
    if iso_code and iso_code in idx:
        return idx[iso_code]
    canonical = normalize_country_name(member_state)
    return idx.get(canonical) or idx.get(member_state)


# ---------------------------------------------------------------------------
# Main import
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


def _import(session, csv_path: Path, dry_run: bool) -> tuple[int, int]:
    updated = skipped = 0
    idx = _build_country_index(session)
    missing_aliases: list[str] = []

    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            member_state = (row.get("Member State") or "").strip()
            iso_code = (row.get("ISO Code") or "").strip()
            m49 = (row.get("M49 Code") or "").strip().lstrip("0") or None
            start = _parse_date(row.get("Start date", ""))
            end = _parse_date(row.get("End date", ""))
            other_names = (row.get("Other Names") or "").strip()
            later_name = (row.get("Earlier or Later Name") or "").strip()

            country_id = _find_country(idx, member_state, iso_code)
            if country_id is None:
                log.debug("No country row for %r (iso=%r) — skipping.", member_state, iso_code)
                # Flag potential missing aliases
                if member_state:
                    missing_aliases.append(member_state)
                skipped += 1
                continue

            log.info(
                "UPDATE country id=%d  %r  m49=%s  since=%s  end=%s",
                country_id, member_state, m49, start, end,
            )
            if not dry_run:
                row_obj = session.query(Country).get(country_id)
                if m49 and not row_obj.m49:
                    row_obj.m49 = m49
                if start and not row_obj.un_member_since:
                    row_obj.un_member_since = start
                if end and not row_obj.un_member_end:
                    row_obj.un_member_end = end
                session.flush()
            updated += 1

            # Log any variant names that might be missing from country_aliases
            variants = [v.strip() for v in other_names.split(",") if v.strip()]
            if later_name:
                variants.append(later_name)
            for v in variants:
                canonical = normalize_country_name(v)
                if canonical != member_state and v not in idx:
                    log.debug("Potential missing alias: %r → %r", v, member_state)

    if missing_aliases:
        log.warning(
            "%d member state rows had no matching country in DB: %s",
            len(missing_aliases),
            ", ".join(missing_aliases[:10]),
        )
    return updated, skipped


def import_undl_member_states(
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
        csv_path = _DATA_DIR / "member_states_auths_2025-12-02_rev-1.csv"

    _download(_CSV_URL, csv_path, force=download)

    with get_session(engine) as session:
        updated, skipped = _import(session, csv_path, dry_run)

    action = "Would update" if dry_run else "Updated"
    log.info("%s %d country rows (%d skipped).", action, updated, skipped)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Enrich countries table from DHL UN Member States dataset.",
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
    import_undl_member_states(
        db_url=args.db,
        csv_path=Path(args.csv) if args.csv else None,
        download=args.download,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
