#!/usr/bin/env python3
"""Generate src/extraction/unbis_subjects.py from the UNBIS Thesaurus.

Downloads the UN Thesaurus SKOS/Turtle file from the UN Digital Library,
parses it with rdflib, and writes a static Python mapping file that maps
English UNBIS preferred labels to their top-level concept scheme.

The generated file is committed to the repository so that rdflib is not
required at runtime — only when regenerating after a new thesaurus release.

UN Thesaurus
------------
  United Nations. (2025). UN Thesaurus (UNBIS).
  UN Digital Library. https://digitallibrary.un.org/record/4075456

Usage
-----
    pip install rdflib
    python scripts/generate_unbis_mapping.py
    python scripts/generate_unbis_mapping.py --ttl path/to/unbist.ttl
    python scripts/generate_unbis_mapping.py --download
"""

from __future__ import annotations

import argparse
import logging
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

log = logging.getLogger(__name__)

_TTL_URL = (
    "https://digitallibrary.un.org/record/4075456/files"
    "/unbist-20250708_2.ttl"
)
_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "undl"
_OUTPUT_FILE = (
    Path(__file__).resolve().parents[1]
    / "src" / "extraction" / "unbis_subjects.py"
)

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


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
# Parse
# ---------------------------------------------------------------------------


def _parse_ttl(ttl_path: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Return (schemes, label_to_scheme).

    schemes         — {scheme_code: scheme_name}  (18 entries)
    label_to_scheme — {en_label_upper: scheme_name}  (~7 000 entries)
    """
    try:
        import rdflib  # noqa: PLC0415
        from rdflib.namespace import SKOS  # noqa: PLC0415
    except ImportError:
        log.error("rdflib is required: pip install rdflib")
        raise

    BASE = "http://metadata.un.org/thesaurus/"

    g = rdflib.Graph()
    log.info("Parsing %s …", ttl_path)
    g.parse(str(ttl_path), format="turtle")
    log.info("Loaded %d triples.", len(g))

    # Scheme names (2-digit codes, excluding :00 = top-level container)
    scheme_names: dict[str, str] = {}
    for s in g.subjects(rdflib.RDF.type, SKOS.ConceptScheme):
        code = str(s).replace(BASE, "")
        if code == "00":
            continue
        for lbl in g.objects(s, SKOS.prefLabel):
            if lbl.language == "en":
                scheme_names[code] = str(lbl).upper()

    # uri → scheme via skos:inScheme (direct membership)
    uri_scheme: dict[str, str] = {}
    for s, _p, o in g.triples((None, SKOS.inScheme, None)):
        code = str(s).replace(BASE, "")
        scheme = str(o).replace(BASE, "")
        if scheme in scheme_names:
            uri_scheme[code] = scheme

    # uri → broader uri (for concepts not directly inScheme)
    broader: dict[str, str] = {}
    for s, _p, o in g.triples((None, SKOS.broader, None)):
        broader[str(s).replace(BASE, "")] = str(o).replace(BASE, "")

    def find_scheme(code: str) -> str | None:
        if code in uri_scheme:
            return uri_scheme[code]
        seen: set[str] = set()
        cur = code
        while cur in broader:
            if cur in seen:
                break
            seen.add(cur)
            cur = broader[cur]
            if cur in uri_scheme:
                return uri_scheme[cur]
        return None

    # English preferred label (uppercase) → scheme name
    label_scheme: dict[str, str] = {}
    for s, _p, o in g.triples((None, SKOS.prefLabel, None)):
        if getattr(o, "language", None) != "en":
            continue
        code = str(s).replace(BASE, "")
        label = str(o).upper()
        scheme_code = find_scheme(code)
        if not scheme_code or scheme_code not in scheme_names:
            continue
        if label not in label_scheme:
            label_scheme[label] = scheme_names[scheme_code]

    log.info(
        "Extracted %d English term mappings across %d schemes.",
        len(label_scheme),
        len(scheme_names),
    )
    return scheme_names, label_scheme


# ---------------------------------------------------------------------------
# Generate Python file
# ---------------------------------------------------------------------------

_FILE_HEADER = '''\
"""UNBIS Thesaurus subject classification.

Auto-generated from the UN Thesaurus (UNBIS Thesaurus) by
``scripts/generate_unbis_mapping.py``.

Source: https://digitallibrary.un.org/record/4075456

Maps English UNBIS preferred labels (uppercase) to their top-level concept
scheme, enabling classification of raw DHL subject strings into UNBIS
categories.

To regenerate after a new thesaurus release::

    pip install rdflib
    python scripts/generate_unbis_mapping.py --download
"""
from __future__ import annotations
'''

_CLASSIFY_FUNC = '''

def classify_unbis(subjects: str) -> str | None:
    """Return the UNBIS scheme name for a pipe-separated DHL subjects string.

    Scans each pipe-separated tag against ``_LABEL_TO_SCHEME``.
    The DHL ``--`` compound notation (e.g. ``UNRWA--ACTIVITIES``) is handled
    by looking up both the full tag and the base term before ``--``.
    Plural variants (``WEAPON`` -> ``WEAPONS``) are also tried.
    Returns the first matching scheme name, or ``None`` if no tag matches.
    """
    if not subjects:
        return None
    tags = [t.strip().upper() for t in subjects.split("|") if t.strip()]
    for tag in tags:
        for candidate in _candidates(tag):
            if candidate in _LABEL_TO_SCHEME:
                return _LABEL_TO_SCHEME[candidate]
    return None


def _candidates(tag: str) -> list[str]:
    """Return lookup variants for a single DHL subject tag (uppercase)."""
    base = tag.split("--")[0].strip()
    variants = [tag, base, base + "S", base + "ES"]
    seen: set[str] = set()
    result = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result
'''


def _write_python(
    schemes: dict[str, str],
    label_scheme: dict[str, str],
    out: Path,
) -> None:
    parts = [_FILE_HEADER, "\n"]

    parts.append("# 18 UNBIS top-level concept scheme names\n")
    parts.append("SCHEMES: dict[str, str] = {\n")
    for code in sorted(schemes):
        parts.append(f"    {code!r}: {schemes[code]!r},\n")
    parts.append("}\n\n")

    parts.append(
        f"# English preferred labels (uppercase) -> UNBIS scheme name\n"
        f"# {len(label_scheme):,} entries derived from the UNBIS Thesaurus.\n"
    )
    parts.append("_LABEL_TO_SCHEME: dict[str, str] = {\n")
    for label in sorted(label_scheme):
        parts.append(f"    {label!r}: {label_scheme[label]!r},\n")
    parts.append("}\n")

    parts.append(_CLASSIFY_FUNC)

    out.write_text("".join(parts))
    log.info("Written %s (%d bytes).", out, out.stat().st_size)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def generate(
    ttl_path: Path | None = None,
    output: Path | None = None,
    download: bool = False,
) -> None:
    if ttl_path is None:
        ttl_path = _DATA_DIR / "unbist.ttl"
    if output is None:
        output = _OUTPUT_FILE
    _download(_TTL_URL, ttl_path, force=download)
    schemes, label_scheme = _parse_ttl(ttl_path)
    _write_python(schemes, label_scheme, output)


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Generate src/extraction/unbis_subjects.py "
            "from the UNBIS Thesaurus."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--ttl",
        default=None,
        help="Local Turtle file path (downloaded if absent)",
    )
    p.add_argument("--output", default=None, help="Output Python file")
    p.add_argument(
        "--download",
        action="store_true",
        help="Force re-download even if cached TTL exists",
    )
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    generate(
        ttl_path=Path(args.ttl) if args.ttl else None,
        output=Path(args.output) if args.output else None,
        download=args.download,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
