#!/usr/bin/env python3
"""Import UN Security Council veto data from the UN Peace & Security Data Hub.

Downloads the DPPA-SCVETOES dataset (CSV, ~71 KB) from the Humanitarian Data
Exchange and populates two new tables:

  ``vetoes``          — one row per vetoed draft resolution
  ``veto_countries``  — one row per (veto, vetoing P5 country)

Vetoed draft resolutions never become adopted resolutions and are therefore
absent from the UNDL voting CSV.  This dataset covers all 1946–present SC
vetoes and links each to the corresponding meeting record (``S/PV.XXXX``) and
``documents`` row where available.

The five P5 country columns in the CSV (``china``, ``russian_federation_ussr``,
``france``, ``united_states``, ``united_kingdom``) are mapped to ``country_id``
FKs via ISO-3 codes.

Usage
-----
    python scripts/import_sc_vetoes.py
    python scripts/import_sc_vetoes.py --db postgresql://...
    python scripts/import_sc_vetoes.py --download          # force re-download
    python scripts/import_sc_vetoes.py --dry-run
    python scripts/import_sc_vetoes.py --verbose

Source
------
  United Nations DPPA. (2025). Security Council Data - Vetoes Since 1946.
  UN Peace & Security Data Hub / Humanitarian Data Exchange.
  https://data.humdata.org/dataset/dppa-scvetoes
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
import urllib.request
from datetime import date as _Date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402

log = logging.getLogger(__name__)

_CACHE_DIR = Path(__file__).resolve().parents[1] / "data" / "dppa"
_CACHE_FILE = _CACHE_DIR / "dppa-scvetoes.csv"
_DOWNLOAD_URL = (
    "https://data.humdata.org/dataset/f67cf146-1cda-44e3-b468-2b086d85cb5a"
    "/resource/12377ab6-e4de-46cb-98b5-7c89ba18115b/download/dppa-scvetoes.csv"
)

# CSV column name → ISO-3 code
_P5_COLUMNS: dict[str, str] = {
    "china": "CHN",
    "russian_federation_ussr": "RUS",
    "france": "FRA",
    "united_states": "USA",
    "united_kingdom": "GBR",
}


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def _ensure_schema(session: Session) -> None:
    session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS vetoes (
                id           SERIAL PRIMARY KEY,
                dppa_id      INTEGER UNIQUE NOT NULL,
                draft_symbol TEXT,
                date         DATE,
                meeting_symbol VARCHAR(30),
                document_id  INTEGER REFERENCES documents(id) ON DELETE SET NULL,
                agenda       TEXT,
                short_agenda TEXT,
                n_vetoing_pm INTEGER,
                dppa_url     VARCHAR(500),
                last_update  DATE
            )
            """
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_vetoes_draft "
            "ON vetoes (draft_symbol)"
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_vetoes_document "
            "ON vetoes (document_id)"
        )
    )
    session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS veto_countries (
                id         SERIAL PRIMARY KEY,
                veto_id    INTEGER NOT NULL REFERENCES vetoes(id) ON DELETE CASCADE,
                country_id INTEGER NOT NULL REFERENCES countries(id) ON DELETE CASCADE,
                UNIQUE (veto_id, country_id)
            )
            """
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_veto_countries_country "
            "ON veto_countries (country_id)"
        )
    )
    session.commit()
    log.info("vetoes / veto_countries schema ready.")


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


def _download(force: bool = False) -> Path:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if _CACHE_FILE.exists() and not force:
        log.info("Using cached %s", _CACHE_FILE)
        return _CACHE_FILE
    log.info("Downloading DPPA-SCVETOES CSV …")
    req = urllib.request.Request(
        _DOWNLOAD_URL,
        headers={"User-Agent": "un-extractor/1.0 (research)"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
    _CACHE_FILE.write_bytes(data)
    log.info("Saved %d bytes to %s", len(data), _CACHE_FILE)
    return _CACHE_FILE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_date(s: str) -> _Date | None:
    s = s.strip()
    if not s:
        return None
    try:
        return _Date.fromisoformat(s)
    except ValueError:
        return None


def _meeting_symbol(record: str) -> str | None:
    """Convert bare PV number (e.g. '10000') to 'S/PV.10000'."""
    r = record.strip()
    if not r or not r.isdigit():
        return None
    return f"S/PV.{r}"


def _build_iso3_index(session: Session) -> dict[str, int]:
    rows = session.execute(
        text("SELECT iso3, id FROM countries WHERE iso3 IS NOT NULL")
    ).fetchall()
    return {iso3.upper(): cid for iso3, cid in rows}


def _find_document_id(session: Session, symbol: str) -> int | None:
    row = session.execute(
        text("SELECT id FROM documents WHERE symbol = :s"), {"s": symbol}
    ).fetchone()
    return row[0] if row else None


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------


def import_sc_vetoes(
    db_url: str | None = None,
    csv_path: Path | None = None,
    force_download: bool = False,
    dry_run: bool = False,
) -> None:
    if csv_path is None:
        csv_path = _download(force=force_download)

    engine = get_engine(db_url)
    create_schema(engine)

    with get_session(engine) as session:
        _ensure_schema(session)
        iso3_to_id = _build_iso3_index(session)

    p5_country_ids = {
        col: iso3_to_id[iso3]
        for col, iso3 in _P5_COLUMNS.items()
        if iso3 in iso3_to_id
    }
    missing = set(_P5_COLUMNS) - set(p5_country_ids)
    if missing:
        log.warning("P5 countries not found in DB: %s", missing)

    inserted = updated = skipped = 0

    with get_session(engine) as session:
        with csv_path.open(newline="", encoding="utf-8-sig") as fh:
            for row in csv.DictReader(fh):
                dppa_id_str = row.get("id", "").strip()
                if not dppa_id_str.isdigit():
                    continue
                dppa_id = int(dppa_id_str)

                draft_symbol = row.get("draft_res#", "").strip() or None
                vote_date = _parse_date(row.get("date", ""))
                record = row.get("record", "").strip()
                meeting_symbol = _meeting_symbol(record)
                agenda = row.get("agenda", "").strip() or None
                short_agenda = row.get("short_agenda", "").strip() or None
                n_pm_str = row.get("#_of_pms", "").strip()
                n_pm = int(n_pm_str) if n_pm_str.isdigit() else None
                dppa_url = row.get("url_for_res#", "").strip() or None
                last_update = _parse_date(row.get("last_update", ""))

                vetoing = [
                    col for col in _P5_COLUMNS
                    if row.get(col, "").strip() == "1"
                ]
                vetoing_ids = [
                    p5_country_ids[col]
                    for col in vetoing
                    if col in p5_country_ids
                ]

                document_id = None
                if meeting_symbol:
                    document_id = _find_document_id(session, meeting_symbol)

                # Check if already exists
                existing = session.execute(
                    text("SELECT id FROM vetoes WHERE dppa_id = :d"),
                    {"d": dppa_id},
                ).fetchone()

                if dry_run:
                    log.debug(
                        "Would upsert veto dppa_id=%d draft=%s date=%s vetoed_by=%s",
                        dppa_id,
                        draft_symbol,
                        vote_date,
                        [_P5_COLUMNS[c] for c in vetoing],
                    )
                    if existing:
                        updated += 1
                    else:
                        inserted += 1
                    continue

                if existing:
                    veto_id = existing[0]
                    session.execute(
                        text(
                            """
                            UPDATE vetoes SET
                                draft_symbol = :draft,
                                date         = :date,
                                meeting_symbol = :ms,
                                document_id  = :doc_id,
                                agenda       = :agenda,
                                short_agenda = :short_agenda,
                                n_vetoing_pm = :n_pm,
                                dppa_url     = :url,
                                last_update  = :lu
                            WHERE dppa_id = :dppa_id
                            """
                        ),
                        {
                            "draft": draft_symbol,
                            "date": vote_date,
                            "ms": meeting_symbol,
                            "doc_id": document_id,
                            "agenda": agenda,
                            "short_agenda": short_agenda,
                            "n_pm": n_pm,
                            "url": dppa_url,
                            "lu": last_update,
                            "dppa_id": dppa_id,
                        },
                    )
                    updated += 1
                else:
                    result = session.execute(
                        text(
                            """
                            INSERT INTO vetoes
                                (dppa_id, draft_symbol, date, meeting_symbol,
                                 document_id, agenda, short_agenda,
                                 n_vetoing_pm, dppa_url, last_update)
                            VALUES
                                (:dppa_id, :draft, :date, :ms,
                                 :doc_id, :agenda, :short_agenda,
                                 :n_pm, :url, :lu)
                            RETURNING id
                            """
                        ),
                        {
                            "dppa_id": dppa_id,
                            "draft": draft_symbol,
                            "date": vote_date,
                            "ms": meeting_symbol,
                            "doc_id": document_id,
                            "agenda": agenda,
                            "short_agenda": short_agenda,
                            "n_pm": n_pm,
                            "url": dppa_url,
                            "lu": last_update,
                        },
                    )
                    veto_id = result.fetchone()[0]
                    inserted += 1

                # Upsert veto_countries
                for cid in vetoing_ids:
                    session.execute(
                        text(
                            """
                            INSERT INTO veto_countries (veto_id, country_id)
                            VALUES (:vid, :cid)
                            ON CONFLICT (veto_id, country_id) DO NOTHING
                            """
                        ),
                        {"vid": veto_id, "cid": cid},
                    )

        if not dry_run:
            session.commit()

    action = "Would insert/update" if dry_run else "Inserted/updated"
    log.info(
        "%s %d vetoes (%d new, %d updated); %d skipped.",
        action,
        inserted + updated,
        inserted,
        updated,
        skipped,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    p = argparse.ArgumentParser(
        description="Import UN Security Council veto data from DPPA-SCVETOES.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument(
        "--csv",
        default=None,
        metavar="PATH",
        help="Path to local dppa-scvetoes.csv (skips download)",
    )
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
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    import_sc_vetoes(
        db_url=args.db,
        csv_path=Path(args.csv) if args.csv else None,
        force_download=args.download,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
