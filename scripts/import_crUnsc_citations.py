#!/usr/bin/env python3
"""Import CR-UNSC citation network into the database.

Downloads ``CITATIONS_GRAPHML.zip`` from the CR-UNSC Zenodo release, parses
the GraphML edge list, and populates the ``resolution_citations`` table.

Each edge ``(citing_node, cited_node)`` in the GraphML file represents one
resolution citing another.  Node IDs are resolution symbols of the form
``S/RES/N`` (SC resolutions) or ``A/RES/N/M`` (GA resolutions).

After inserting edges, the script back-fills ``cited_id`` for any cited symbol
already present in the ``resolutions`` table.

CR-UNSC dataset
---------------
  Fobbe, S. (2025). CR-UNSC: Compilation of Resolutions of the United
  Nations Security Council. Zenodo. https://doi.org/10.5281/zenodo.7319780

Usage
-----
    python scripts/import_crUnsc_citations.py
    python scripts/import_crUnsc_citations.py --db postgresql://user:pass@host/db
    python scripts/import_crUnsc_citations.py --zip path/to/CITATIONS_GRAPHML.zip
    python scripts/import_crUnsc_citations.py --download
    python scripts/import_crUnsc_citations.py --dry-run
    python scripts/import_crUnsc_citations.py --verbose
"""

from __future__ import annotations

import argparse
import logging
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402
from src.db.models import Resolution, ResolutionCitation  # noqa: E402

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Zenodo download URL
# ---------------------------------------------------------------------------

_GRAPHML_ZIP_URL = (
    "https://zenodo.org/api/records/15154519/files"
    "/CR-UNSC_2025-12-22_CITATIONS_GRAPHML.zip/content"
)

_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "crUnsc"

# GraphML namespace (igraph uses the /xmlns variant)
_GML_NS = "http://graphml.graphdrawing.org/xmlns"


# ---------------------------------------------------------------------------
# Schema migration
# ---------------------------------------------------------------------------


def _ensure_table(session: Session) -> None:
    """Create resolution_citations table and indexes if missing."""
    session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS resolution_citations (
                id          SERIAL      PRIMARY KEY,
                citing_id   INTEGER     NOT NULL
                                        REFERENCES resolutions(id)
                                        ON DELETE CASCADE,
                cited_symbol TEXT       NOT NULL,
                cited_id    INTEGER
                                        REFERENCES resolutions(id)
                                        ON DELETE SET NULL,
                weight      INTEGER     NOT NULL DEFAULT 1,
                UNIQUE (citing_id, cited_symbol)
            )
            """
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_rc_citing ON resolution_citations (citing_id)"
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_rc_cited ON resolution_citations (cited_id)"
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
# GraphML parsing
# ---------------------------------------------------------------------------


def _parse_graphml(zip_path: Path) -> list[tuple[str, str, int]]:
    """Parse the GraphML zip and return a list of (citing_symbol, cited_symbol, weight).

    The GraphML may contain multiple GraphML files; we parse all of them.
    Edge weights are accumulated when duplicate edges appear.
    """
    edge_weights: dict[tuple[str, str], int] = defaultdict(int)

    with zipfile.ZipFile(zip_path) as zf:
        graphml_names = [n for n in zf.namelist() if n.lower().endswith(".graphml")]
        if not graphml_names:
            raise ValueError(f"No .graphml files found inside {zip_path}")
        log.info("Found %d GraphML file(s) in zip.", len(graphml_names))

        for gname in graphml_names:
            log.info("Parsing %s …", gname)
            data = zf.read(gname)
            root = ET.fromstring(data)

            # Build node_id → resolution symbol from <data key="v_symbol"> elements.
            # Nodes look like:
            #   <node id="n0">
            #     <data key="v_symbol">S/RES/1(1946)</data>
            #     ...
            #   </node>
            node_symbol: dict[str, str] = {}
            for node in root.iter(f"{{{_GML_NS}}}node"):
                nid = node.get("id", "")
                for data_el in node.iter(f"{{{_GML_NS}}}data"):
                    if data_el.get("key") == "v_symbol":
                        sym = (data_el.text or "").strip()
                        if sym:
                            node_symbol[nid] = sym
                        break

            # Collect edges; weight is stored in <data key="e_weight">.
            # Edges look like:
            #   <edge source="n2510" target="n2587">
            #     <data key="e_weight">1</data>
            #   </edge>
            for edge in root.iter(f"{{{_GML_NS}}}edge"):
                src = edge.get("source", "")
                tgt = edge.get("target", "")
                citing = node_symbol.get(src)
                cited = node_symbol.get(tgt)
                if not citing or not cited or citing == cited:
                    continue
                weight = 1
                for data_el in edge.iter(f"{{{_GML_NS}}}data"):
                    if data_el.get("key") == "e_weight":
                        try:
                            weight = int(data_el.text or 1)
                        except ValueError:
                            pass
                        break
                edge_weights[(citing, cited)] += weight

    result = [(citing, cited, w) for (citing, cited), w in edge_weights.items()]
    log.info("Parsed %d unique citation edges.", len(result))
    return result


# ---------------------------------------------------------------------------
# Symbol lookup helpers
# ---------------------------------------------------------------------------


def _build_symbol_index(session: Session) -> dict[str, int]:
    """Return a mapping from adopted_symbol → resolution.id for all SC resolutions.

    We also index the plain ``S/RES/N`` prefix (without the year parenthetical)
    so that CR-UNSC symbols like ``S/RES/156`` match ``S/RES/156(1980)``  in
    the DB.
    """
    rows = (
        session.query(Resolution.id, Resolution.adopted_symbol)
        .filter(Resolution.body == "SC")
        .filter(Resolution.adopted_symbol.isnot(None))
        .all()
    )
    idx: dict[str, int] = {}
    for res_id, sym in rows:
        if sym:
            idx[sym] = res_id
            # Strip year parenthetical: "S/RES/156(1980)" → "S/RES/156"
            plain = sym.split("(")[0].strip()
            if plain not in idx:
                idx[plain] = res_id
    return idx


def _lookup_resolution(
    session: Session,
    symbol: str,
    idx: dict[str, int],
) -> int | None:
    """Return resolution.id for a symbol, or None."""
    if symbol in idx:
        return idx[symbol]
    plain = symbol.split("(")[0].strip()
    return idx.get(plain)


# ---------------------------------------------------------------------------
# Main import logic
# ---------------------------------------------------------------------------


def _import_citations(
    session: Session,
    edges: list[tuple[str, str, int]],
    dry_run: bool,
) -> tuple[int, int, int]:
    """Upsert citation edges.  Returns (inserted, updated, skipped)."""
    inserted = updated = skipped = 0

    symbol_idx = _build_symbol_index(session)
    log.info("Symbol index built: %d SC resolutions.", len(symbol_idx))

    for citing_symbol, cited_symbol, weight in edges:
        citing_id = _lookup_resolution(session, citing_symbol, symbol_idx)
        if citing_id is None:
            log.debug("Citing resolution not in DB: %s — skipping.", citing_symbol)
            skipped += 1
            continue

        cited_id = _lookup_resolution(session, cited_symbol, symbol_idx)

        existing = (
            session.query(ResolutionCitation)
            .filter_by(citing_id=citing_id, cited_symbol=cited_symbol)
            .first()
        )

        if existing is not None:
            if existing.weight != weight or existing.cited_id != cited_id:
                log.debug(
                    "UPDATE citation id=%d  %s→%s  weight=%d",
                    existing.id,
                    citing_symbol,
                    cited_symbol,
                    weight,
                )
                if not dry_run:
                    existing.weight = weight
                    existing.cited_id = cited_id
                    session.flush()
                updated += 1
        else:
            log.debug(
                "INSERT citation  %s→%s  weight=%d  cited_id=%s",
                citing_symbol,
                cited_symbol,
                weight,
                cited_id,
            )
            if not dry_run:
                rc = ResolutionCitation(
                    citing_id=citing_id,
                    cited_symbol=cited_symbol,
                    cited_id=cited_id,
                    weight=weight,
                )
                session.add(rc)
                session.flush()
            inserted += 1

    return inserted, updated, skipped


def import_crUnsc_citations(
    db_url: str | None = None,
    zip_path: Path | None = None,
    download: bool = False,
    dry_run: bool = False,
) -> None:
    engine = get_engine(db_url)
    create_schema(engine)

    with get_session(engine) as session:
        _ensure_table(session)

    if zip_path is None:
        zip_path = _DATA_DIR / "CR-UNSC_2025-12-22_CITATIONS_GRAPHML.zip"

    _download(_GRAPHML_ZIP_URL, zip_path, force=download)

    edges = _parse_graphml(zip_path)

    with get_session(engine) as session:
        inserted, updated, skipped = _import_citations(session, edges, dry_run)

    action = "Would insert" if dry_run else "Inserted"
    log.info(
        "%s %d citation edges, updated %d, skipped %d (citing resolution not in DB).",
        action,
        inserted,
        updated,
        skipped,
    )


def main() -> int:
    p = argparse.ArgumentParser(
        description="Import CR-UNSC citation network into the database.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument(
        "--zip", default=None, help="Path to CITATIONS_GRAPHML.zip (local file)"
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
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    import_crUnsc_citations(
        db_url=args.db,
        zip_path=Path(args.zip) if args.zip else None,
        download=args.download,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
