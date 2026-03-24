#!/usr/bin/env python3
"""Import SC debate speeches from the Schönfeld et al. Harvard Dataverse corpus.

Downloads three files from Harvard Dataverse (doi:10.7910/DVN/KGVSYH):
  meta.tsv      (591 KB)  — meeting metadata (symbol, date, topic)
  speaker.tsv   (31.5 MB) — speech-level metadata (speaker, country, position)
  speeches.tar  (452 MB)  — one .txt file per speech

For each speech:
  - Matches or creates a ``documents`` row (by S/PV.XXXX symbol)
  - Matches or creates a ``speakers`` row (by name + country)
  - Creates a ``document_items`` row for the meeting topic (one per meeting)
  - Inserts the speech text into the ``speeches`` table

A meeting whose document row already has speech content in the DB is
skipped to avoid duplicating text already extracted from PDF.

Source
------
  Schönfeld et al. (2019 / 2025). The UN Security Council Debates.
  Harvard Dataverse, doi:10.7910/DVN/KGVSYH (v6.1, Feb 2025).
  CC0 licence.  Reference: https://arxiv.org/abs/1906.10969
  Coverage: 1995-01-01 – 2020-12-29, 106,302 speeches, 6,233 meetings.

Usage
-----
    python scripts/import_sc_debates.py
    python scripts/import_sc_debates.py --db postgresql://...
    python scripts/import_sc_debates.py --download          # force re-download
    python scripts/import_sc_debates.py --dry-run
    python scripts/import_sc_debates.py --limit 500         # first N speeches
    python scripts/import_sc_debates.py --skip-existing     # skip docs with speeches
"""

from __future__ import annotations

import argparse
import csv
import io
import logging
import sys
import tarfile
import urllib.request
from collections import defaultdict
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402
from src.db.models import (  # noqa: E402
    Country,
    Document,
    DocumentItem,
    Speaker,
    Speech,
)
from src.extraction.country_aliases import normalize_country_name  # noqa: E402

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dataverse file IDs (doi:10.7910/DVN/KGVSYH v6.1)
# ---------------------------------------------------------------------------

_BASE = "https://dataverse.harvard.edu/api/access/datafile"
_META_URL = f"{_BASE}/10809806"       # meta.tsv    (591 KB)
_SPEAKER_URL = f"{_BASE}/10809807"    # speaker.tsv (31.5 MB)
_SPEECHES_URL = f"{_BASE}/10809805"   # speeches.tar (452 MB)

_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "sc_debates"

_BATCH = 500   # speeches per DB commit


# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------


_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"
    ),
    "Accept": "*/*",
}


def _download(url: str, dest: Path, force: bool = False) -> Path:
    if dest.exists() and not force:
        log.info("Using cached %s", dest.name)
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    log.info("Downloading %s → %s …", url, dest.name)
    req = urllib.request.Request(url, headers=_HEADERS)
    with urllib.request.urlopen(req) as resp, dest.open("wb") as fh:
        while chunk := resp.read(1 << 20):  # 1 MB chunks
            fh.write(chunk)
    log.info("Downloaded %s (%.1f MB)", dest.name, dest.stat().st_size / 1e6)
    return dest


# ---------------------------------------------------------------------------
# TSV parsing
# ---------------------------------------------------------------------------


def _parse_meta(path: Path) -> dict[str, dict]:
    """Return {meeting_symbol: {date, topic, spv}} from meta.tsv.

    meta.tsv columns: (index) basename date topic year month day spv num_speeches
    Symbol is derived from the spv column: S/PV.{spv}
    """
    result: dict[str, dict] = {}
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh, delimiter="\t")
        for row in reader:
            spv = row.get("spv", "").strip()
            if not spv:
                continue
            sym = f"S/PV.{spv}"
            result[sym] = {
                "date": row.get("date", "").strip(),
                "topic": row.get("topic", "").strip(),
                "spv": spv,
            }
    return result


def _parse_speakers(path: Path) -> dict[str, dict]:
    """Return {filename: row_dict} from speaker.tsv.

    Key fields: filename, meeting_symbol, speech_number, speaker,
    speaker_country, role, agenda_item1, agenda_item2, date.
    """
    result: dict[str, dict] = {}
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh, delimiter="\t")
        for row in reader:
            fname = row.get("filename", "").strip()
            if fname:
                result[fname] = row
    return result


# ---------------------------------------------------------------------------
# DB index helpers
# ---------------------------------------------------------------------------


def _build_doc_index(session: Session) -> dict[str, int]:
    """symbol → document.id for SC documents."""
    rows = session.query(Document.symbol, Document.id).filter_by(body="SC").all()
    return {sym: did for sym, did in rows}


def _docs_with_speeches(session: Session) -> set[int]:
    """Set of document_ids that already have speech rows."""
    from sqlalchemy import text
    result = session.execute(
        text("SELECT DISTINCT document_id FROM speeches WHERE document_id IN "
             "(SELECT id FROM documents WHERE body='SC')")
    )
    return {row[0] for row in result}


def _build_country_index(session: Session) -> dict[str, int]:
    rows = session.query(Country.name, Country.id).all()
    return {normalize_country_name(name): cid for name, cid in rows}


def _build_speaker_index(session: Session) -> dict[tuple[str, int | None], int]:
    rows = session.query(Speaker.name, Speaker.country_id, Speaker.id).all()
    return {(name, cid): sid for name, cid, sid in rows}


# ---------------------------------------------------------------------------
# Get-or-create helpers
# ---------------------------------------------------------------------------


def _get_or_create_doc(
    session: Session,
    doc_idx: dict[str, int],
    symbol: str,
    meeting_date: str,
    topic: str,
) -> int:
    if symbol in doc_idx:
        return doc_idx[symbol]

    # Parse spv number from symbol (S/PV.3026 → 3026)
    spv = 0
    if symbol.startswith("S/PV."):
        try:
            spv = int(symbol[5:])
        except ValueError:
            pass

    d: date | None = None
    try:
        d = date.fromisoformat(meeting_date)
    except (ValueError, TypeError):
        pass

    doc = Document(
        symbol=symbol,
        body="SC",
        meeting_number=spv,
        date=d,
        location=None,
        pdf_path=None,
    )
    session.add(doc)
    session.flush()
    doc_idx[symbol] = doc.id
    log.debug("Created document %s id=%d", symbol, doc.id)
    return doc.id


def _get_or_create_item(
    session: Session,
    item_cache: dict[int, int],
    doc_id: int,
    title: str,
) -> int:
    if doc_id in item_cache:
        return item_cache[doc_id]

    item = DocumentItem(
        document_id=doc_id,
        position=0,
        item_type="other_item",
        title=title or "SC meeting",
        agenda_number=None,
        continued=False,
    )
    session.add(item)
    session.flush()
    item_cache[doc_id] = item.id
    return item.id


def _get_or_create_speaker(
    session: Session,
    spk_idx: dict[tuple[str, int | None], int],
    name: str,
    country_id: int | None,
    role: str | None,
) -> int:
    key = (name, country_id)
    if key in spk_idx:
        return spk_idx[key]

    spk = Speaker(
        name=name,
        country_id=country_id,
        role=role or None,
        organization=None,
        title=None,
    )
    session.add(spk)
    session.flush()
    spk_idx[key] = spk.id
    return spk.id


# ---------------------------------------------------------------------------
# Main import
# ---------------------------------------------------------------------------


def _import(
    session: Session,
    speaker_rows: dict[str, dict],
    speeches_tar: Path,
    doc_idx: dict[str, int],
    skip_doc_ids: set[int],
    country_idx: dict[str, int],
    spk_idx: dict[tuple[str, int | None], int],
    dry_run: bool,
    limit: int | None,
) -> tuple[int, int, int]:
    inserted = skipped_existing = skipped_no_meta = 0
    item_cache: dict[int, int] = {}  # doc_id → item_id

    with tarfile.open(speeches_tar, "r") as tf:
        for member in tf:
            if not member.isfile():
                continue

            fname = Path(member.name).name  # strip any leading path
            meta = speaker_rows.get(fname)
            if meta is None:
                log.debug("No speaker.tsv row for %s — skipping.", fname)
                skipped_no_meta += 1
                continue

            symbol = (meta.get("meeting_symbol") or "").strip()
            if not symbol:
                skipped_no_meta += 1
                continue

            meeting_date = (meta.get("date") or "").strip()
            topic = (meta.get("agenda_item1") or meta.get("topic") or "").strip()
            speaker_name = (meta.get("speaker") or "").strip()
            speaker_country_raw = (meta.get("speaker_country") or "").strip()
            role = (meta.get("role") or "").strip() or None
            try:
                position = int(meta.get("speech_number") or 0)
            except ValueError:
                position = 0

            # Resolve country
            canonical = normalize_country_name(speaker_country_raw)
            country_id = country_idx.get(canonical)

            # Get or create document
            if not dry_run:
                doc_id = _get_or_create_doc(
                    session, doc_idx, symbol, meeting_date, topic
                )
            else:
                doc_id = doc_idx.get(symbol, -1)

            # Skip if document already has extracted speeches
            if doc_id in skip_doc_ids:
                skipped_existing += 1
                continue

            # Read speech text
            fobj = tf.extractfile(member)
            if fobj is None:
                skipped_no_meta += 1
                continue
            text = fobj.read().decode("utf-8", errors="replace").strip()
            if not text:
                skipped_no_meta += 1
                continue

            if not dry_run:
                item_id = _get_or_create_item(session, item_cache, doc_id, topic)
                speaker_id = _get_or_create_speaker(
                    session, spk_idx, speaker_name, country_id, role
                )
                speech = Speech(
                    document_id=doc_id,
                    item_id=item_id,
                    speaker_id=speaker_id,
                    text=text,
                    position_in_document=position,
                    position_in_item=position,
                    language="English",
                )
                session.add(speech)

            inserted += 1
            if inserted % _BATCH == 0:
                if not dry_run:
                    session.flush()
                log.info(
                    "Progress: %d inserted, %d skipped (existing), %d skipped (no meta)",
                    inserted, skipped_existing, skipped_no_meta,
                )

            if limit and inserted >= limit:
                log.info("Reached --limit %d, stopping.", limit)
                break

    if not dry_run:
        session.flush()

    return inserted, skipped_existing, skipped_no_meta


def _ensure_role_wide(session: Session) -> None:
    result = session.execute(
        text(
            "SELECT character_maximum_length FROM information_schema.columns "
            "WHERE table_name='speakers' AND column_name='role'"
        )
    ).fetchone()
    if result and result[0] and result[0] < 500:
        log.info("Widening speakers.role to VARCHAR(500) …")
        session.execute(text("ALTER TABLE speakers ALTER COLUMN role TYPE VARCHAR(500)"))
        session.commit()


def _ensure_session_nullable(session: Session) -> None:
    result = session.execute(
        text(
            "SELECT is_nullable FROM information_schema.columns "
            "WHERE table_name='documents' AND column_name='session'"
        )
    ).fetchone()
    if result and result[0] == "NO":
        log.info("Dropping NOT NULL constraint on documents.session …")
        session.execute(text("ALTER TABLE documents ALTER COLUMN session DROP NOT NULL"))
        session.commit()


def import_sc_debates(
    db_url: str | None = None,
    data_dir: Path | None = None,
    download: bool = False,
    dry_run: bool = False,
    skip_existing: bool = True,
    limit: int | None = None,
) -> None:
    if data_dir is None:
        data_dir = _DATA_DIR

    meta_path = _download(_META_URL, data_dir / "meta.tsv", force=download)
    speaker_path = _download(_SPEAKER_URL, data_dir / "speaker.tsv", force=download)
    speeches_path = _download(_SPEECHES_URL, data_dir / "speeches.tar", force=download)

    log.info("Parsing speaker.tsv …")
    speaker_rows = _parse_speakers(speaker_path)
    log.info("Loaded %d speech rows from speaker.tsv.", len(speaker_rows))

    engine = get_engine(db_url)
    create_schema(engine)

    with get_session(engine) as session:
        _ensure_session_nullable(session)
        _ensure_role_wide(session)

    with get_session(engine) as session:
        log.info("Building indexes …")
        doc_idx = _build_doc_index(session)
        log.info("  %d existing SC documents.", len(doc_idx))
        skip_doc_ids = _docs_with_speeches(session) if skip_existing else set()
        if skip_existing:
            log.info("  %d SC documents already have speeches — will skip.", len(skip_doc_ids))
        country_idx = _build_country_index(session)
        spk_idx = _build_speaker_index(session)

        log.info("Streaming speeches.tar …")
        ins, sk_ex, sk_nm = _import(
            session=session,
            speaker_rows=speaker_rows,
            speeches_tar=speeches_path,
            doc_idx=doc_idx,
            skip_doc_ids=skip_doc_ids,
            country_idx=country_idx,
            spk_idx=spk_idx,
            dry_run=dry_run,
            limit=limit,
        )

    action = "Would insert" if dry_run else "Inserted"
    log.info(
        "%s %d speeches. Skipped: %d (existing), %d (no metadata).",
        action, ins, sk_ex, sk_nm,
    )


def main() -> int:
    p = argparse.ArgumentParser(
        description="Import SC debate speeches from Schönfeld et al. Harvard Dataverse corpus.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="PostgreSQL DSN")
    p.add_argument("--data-dir", default=None, help="Directory for cached downloads")
    p.add_argument("--download", action="store_true", help="Force re-download of files")
    p.add_argument("--dry-run", action="store_true", help="Parse only, no DB writes")
    p.add_argument(
        "--no-skip-existing",
        dest="skip_existing",
        action="store_false",
        help="Import speeches even for meetings already in the DB",
    )
    p.add_argument("--limit", type=int, default=None, help="Stop after N speeches")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )
    import_sc_debates(
        db_url=args.db,
        data_dir=Path(args.data_dir) if args.data_dir else None,
        download=args.download,
        dry_run=args.dry_run,
        skip_existing=args.skip_existing,
        limit=args.limit,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
