#!/usr/bin/env python3
"""Import Voeten/BSV ideal points from the published replication dataset.

Downloads ``Idealpoints.tab`` from the Bailey–Strezhnev–Voeten (2017)
replication package on Harvard Dataverse and upserts every (country, year)
row into ``country_ideal_points`` with ``source = 'voeten_bsv2017'``.

Reference
---------
Bailey, M. A., Strezhnev, A., & Voeten, E. (2017).
Estimating dynamic state preferences from United Nations voting data.
Journal of Conflict Resolution, 61(2), 430–456.
https://doi.org/10.1177/0022002715595700

Dataset DOI: https://doi.org/10.7910/DVN/LEJUQZ

Expected file format (tab-delimited, first row = header):

    ccode   year    Idealpoint  se      Country
    2       1946    1.234       0.078   United States of America
    ...

``ccode`` is the Correlates of War numeric country code.  The script matches
countries first by COW code (via a built-in lookup table for ambiguous cases),
then by ``normalize_country_name`` on the ``Country`` field.

Coverage: ~200 countries, 1946–present (Voeten updates the file periodically).

Usage
-----
    python scripts/import_voeten_ideal_points.py
    python scripts/import_voeten_ideal_points.py --db postgresql://...
    python scripts/import_voeten_ideal_points.py --download          # force re-download
    python scripts/import_voeten_ideal_points.py --file /path/to/Idealpoints.tab
    python scripts/import_voeten_ideal_points.py --dry-run
    python scripts/import_voeten_ideal_points.py --verbose
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import get_engine, get_session  # noqa: E402
from src.extraction.country_aliases import normalize_country_name  # noqa: E402

log = logging.getLogger(__name__)

_CACHE_DIR = Path(__file__).resolve().parents[1] / "data" / "voeten"
_IDEAL_POINTS_FILE = _CACHE_DIR / "Idealpoints.tab"

# Harvard Dataverse dataset DOI for BSV 2017 replication package
_DATAVERSE_DOI = "doi:10.7910/DVN/LEJUQZ"
_DATAVERSE_API = "https://dataverse.harvard.edu/api"

# ---------------------------------------------------------------------------
# COW code → ISO3 for countries where name matching is unreliable
# (former states, name variants, splits/merges)
# ---------------------------------------------------------------------------

_COW_TO_ISO3: dict[int, str] = {
    2: "USA",   # United States of America
    20: "CAN",  # Canada
    40: "CUB",  # Cuba
    41: "HTI",  # Haiti
    42: "DOM",  # Dominican Republic
    51: "JAM",  # Jamaica
    52: "TTO",  # Trinidad and Tobago
    53: "BRB",  # Barbados
    54: "DMA",  # Dominica
    55: "GRD",  # Grenada
    56: "TCA",  # Saint Kitts and Nevis (approx)
    57: "ATG",  # Antigua and Barbuda
    58: "SLC",  # Saint Lucia — no ISO3 match (use name)
    60: "VCT",  # Saint Vincent and the Grenadines
    70: "MEX",  # Mexico
    80: "BLZ",  # Belize
    90: "GTM",  # Guatemala
    91: "HND",  # Honduras
    92: "SLV",  # El Salvador
    93: "NIC",  # Nicaragua
    94: "CRI",  # Costa Rica
    95: "PAN",  # Panama
    100: "COL", # Colombia
    101: "VEN", # Venezuela
    110: "GUY", # Guyana
    115: "SUR", # Suriname
    130: "ECU", # Ecuador
    135: "PER", # Peru
    140: "BRA", # Brazil
    145: "BOL", # Bolivia
    150: "PRY", # Paraguay
    155: "CHL", # Chile
    160: "ARG", # Argentina
    165: "URY", # Uruguay
    200: "GBR", # United Kingdom
    205: "IRL", # Ireland
    210: "NLD", # Netherlands
    211: "BEL", # Belgium
    212: "LUX", # Luxembourg
    220: "FRA", # France
    225: "CHE", # Switzerland
    230: "ESP", # Spain
    235: "PRT", # Portugal
    240: "HAN",  # Hanover (historical — skip)
    245: "BVR",  # Bavaria (historical — skip)
    255: "DEU", # Germany (unified / West Germany)
    260: "DEU", # West Germany (maps to DEU; East = DDR handled by name)
    265: "DDR",  # East Germany — no ISO3, use name
    269: None,   # Historical German minor states
    271: None,   # Wuerttemberg (historical)
    273: None,   # Baden (historical)
    275: None,   # Saxony (historical)
    280: None,   # Thuringian States (historical)
    285: None,   # Prussia (historical)
    290: "POL", # Poland
    300: "AUT", # Austria
    305: "AUT", # Austria-Hungary → Austria (historical; may appear before 1918)
    310: "HUN", # Hungary
    315: "CZE", # Czechoslovakia / Czech Republic
    316: "SVK", # Slovakia
    317: "CZE", # Czech Republic (post-1993)
    325: "ITA", # Italy
    327: None,   # Papal States (historical)
    329: None,   # Two Sicilies (historical)
    331: None,   # Modena (historical)
    332: None,   # Parma (historical)
    335: None,   # Tuscany (historical)
    337: None,   # Sardinia (historical)
    338: "SMR", # San Marino
    339: "MCO", # Monaco
    340: "SRB", # Yugoslavia / Serbia
    341: "XKX", # Kosovo — no standard ISO3
    342: "HRV", # Croatia
    343: "SVN", # Slovenia
    344: "BIH", # Bosnia and Herzegovina
    345: "SRB", # Yugoslavia (maps to Serbia for post-split)
    346: "MKD", # North Macedonia
    347: "MNE", # Montenegro
    349: None,   # Kosovo (COW 347 or 349 depending on edition)
    350: "GRC", # Greece
    352: "CYP", # Cyprus
    355: "BGR", # Bulgaria
    359: "MDA", # Moldova
    360: "ROU", # Romania
    365: "RUS", # Russia / Soviet Union
    366: "EST", # Estonia
    367: "LVA", # Latvia
    368: "LTU", # Lithuania
    369: "FIN", # Finland
    370: "BLR", # Belarus
    371: "UKR", # Ukraine
    372: "GEO", # Georgia
    373: "AZE", # Azerbaijan
    374: "ARM", # Armenia
    375: "FIN", # Finland (pre-1940)
    380: "SWE", # Sweden
    385: "NOR", # Norway
    390: "DNK", # Denmark
    395: "ISL", # Iceland
    402: "CPV", # Cape Verde
    403: "STP", # Sao Tome and Principe
    404: "GNQ", # Equatorial Guinea
    411: "GAB", # Gabon
    412: "COD", # Democratic Republic of the Congo
    420: "UGA", # Uganda
    432: "MLI", # Mali
    433: "SEN", # Senegal
    434: "BEN", # Benin
    435: "MRT", # Mauritania
    436: "NER", # Niger
    437: "CIV", # Cote d'Ivoire
    438: "GIN", # Guinea
    439: "BFA", # Burkina Faso
    450: "LBR", # Liberia
    451: "SLE", # Sierra Leone
    452: "GHA", # Ghana
    461: "TGO", # Togo
    471: "CMR", # Cameroon
    475: "NGA", # Nigeria
    481: "CAF", # Central African Republic
    482: "COD", # Congo, Dem. Rep. (Zaire)
    483: "COG", # Congo
    484: "COD", # Zaire → DRC
    490: "COD", # Democratic Republic of the Congo (all variants)
    500: "UGA", # Uganda (duplicate — handled)
    501: "KEN", # Kenya
    510: "TZA", # Tanzania
    511: "ZNZ", # Zanzibar (historical)
    516: "BDI", # Burundi
    517: "RWA", # Rwanda
    520: "SOM", # Somalia
    522: "DJI", # Djibouti
    530: "ETH", # Ethiopia
    531: "ERI", # Eritrea
    540: "AGO", # Angola
    541: "MOZ", # Mozambique
    551: "ZMB", # Zambia
    552: "ZWE", # Zimbabwe
    553: "MWI", # Malawi
    560: "ZAF", # South Africa
    565: "NAM", # Namibia
    570: "LSO", # Lesotho
    571: "BWA", # Botswana
    572: "SWZ", # Eswatini
    580: "MDG", # Madagascar
    581: "COM", # Comoros
    590: "MUS", # Mauritius
    591: "SYC", # Seychelles
    600: "MAR", # Morocco
    615: "ALG", # Algeria → use name match
    616: "DZA", # Algeria
    620: "LBY", # Libya
    625: "SDN", # Sudan
    626: "SSD", # South Sudan
    630: "IRN", # Iran
    640: "TUR", # Turkey
    645: "IRQ", # Iraq
    651: "EGY", # Egypt
    652: "SYR", # Syria
    660: "LBN", # Lebanon
    663: "JOR", # Jordan
    666: "ISR", # Israel
    670: "SAU", # Saudi Arabia
    678: "YEM", # Yemen
    679: "YEM", # Yemen Arab Republic / PDR Yemen → unified Yemen
    680: "YEM", # People's Democratic Republic of Yemen
    690: "KWT", # Kuwait
    692: "BHR", # Bahrain
    694: "QAT", # Qatar
    696: "ARE", # United Arab Emirates
    698: "OMN", # Oman
    700: "AFG", # Afghanistan
    701: "KAZ", # Kazakhstan
    702: "TJK", # Tajikistan
    703: "KGZ", # Kyrgyzstan
    704: "TKM", # Turkmenistan
    705: "UZB", # Uzbekistan
    710: "CHN", # China
    711: "TWN", # Taiwan (not UN member)
    712: "MNG", # Mongolia
    713: "KOR", # South Korea
    731: "PRK", # North Korea
    732: "KOR", # Republic of Korea
    740: "JPN", # Japan
    750: "IND", # India
    760: "BHU", # Bhutan → use name
    770: "PAK", # Pakistan
    771: "BGD", # Bangladesh
    775: "MMR", # Myanmar / Burma
    780: "LKA", # Sri Lanka
    781: "MDV", # Maldives
    790: "NPL", # Nepal
    800: "THA", # Thailand
    811: "KHM", # Cambodia
    812: "LAO", # Laos
    816: "VNM", # Vietnam
    817: "VNM", # South Vietnam → unified Vietnam
    820: "MYS", # Malaysia
    830: "SGP", # Singapore
    835: "BRN", # Brunei
    840: "PHL", # Philippines
    850: "IDN", # Indonesia
    860: "TLS", # East Timor (Timor-Leste)
    900: "AUS", # Australia
    910: "PNG", # Papua New Guinea
    920: "NZL", # New Zealand
    935: "VUT", # Vanuatu
    940: "SLB", # Solomon Islands
    950: "FJI", # Fiji
    955: "TON", # Tonga
    983: "TUV", # Tuvalu
    986: "KIR", # Kiribati
    987: "WSM", # Samoa
    990: "NRU", # Nauru
    995: "PLW", # Palau
    996: "FSM", # Micronesia
    997: "MHL", # Marshall Islands
}


# ---------------------------------------------------------------------------
# Schema migration
# ---------------------------------------------------------------------------


def _ensure_schema(session: Session) -> None:
    session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS country_ideal_points (
                id          SERIAL PRIMARY KEY,
                country_id  INTEGER REFERENCES countries(id) ON DELETE CASCADE,
                iso3        VARCHAR(3) NOT NULL,
                year        INTEGER NOT NULL,
                ideal_point DOUBLE PRECISION NOT NULL,
                se          DOUBLE PRECISION,
                source      VARCHAR(32) NOT NULL DEFAULT 'voeten_bsv2017',
                UNIQUE (iso3, year)
            )
            """
        )
    )
    # Add source column if schema was created by the older compute_ideal_points.py
    session.execute(
        text(
            """
            ALTER TABLE country_ideal_points
            ADD COLUMN IF NOT EXISTS source VARCHAR(32) NOT NULL DEFAULT 'computed_irt'
            """
        )
    )
    for idx_sql in [
        "CREATE INDEX IF NOT EXISTS ix_cip_country ON country_ideal_points (country_id)",
        "CREATE INDEX IF NOT EXISTS ix_cip_year ON country_ideal_points (year)",
        "CREATE INDEX IF NOT EXISTS ix_cip_source ON country_ideal_points (source)",
    ]:
        session.execute(text(idx_sql))
    session.commit()
    log.info("country_ideal_points schema ready.")


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


def _discover_file_id(doi: str) -> int | None:
    """Query Harvard Dataverse API and return the numeric file ID for Idealpoints.tab."""
    url = f"{_DATAVERSE_API}/datasets/:persistentId/?persistentId={doi}"
    log.debug("Querying Dataverse API: %s", url)
    req = urllib.request.Request(url, headers={"User-Agent": "un-extractor/1.0 (research)"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            meta = json.loads(resp.read())
    except Exception as exc:
        log.warning("Dataverse API query failed: %s", exc)
        return None

    files = (
        meta.get("data", {})
        .get("latestVersion", {})
        .get("files", [])
    )
    for entry in files:
        fname = entry.get("dataFile", {}).get("filename", "")
        if fname.lower() == "idealpoints.tab":
            return entry["dataFile"]["id"]
    log.warning("Idealpoints.tab not found in dataset %s (found: %s)", doi,
                [e.get("dataFile", {}).get("filename") for e in files])
    return None


def _download_ideal_points(dest: Path, force: bool) -> bool:
    """Download Idealpoints.tab to dest.  Returns True on success."""
    if dest.exists() and not force:
        log.info("Using cached %s", dest.name)
        return True

    file_id = _discover_file_id(_DATAVERSE_DOI)
    if file_id is None:
        log.error(
            "Could not locate Idealpoints.tab on Harvard Dataverse (%s).\n"
            "Download it manually from https://doi.org/10.7910/DVN/LEJUQZ\n"
            "and pass --file /path/to/Idealpoints.tab",
            _DATAVERSE_DOI,
        )
        return False

    url = f"{_DATAVERSE_API}/access/datafile/{file_id}"
    log.info("Downloading Idealpoints.tab (file_id=%d) …", file_id)
    req = urllib.request.Request(url, headers={"User-Agent": "un-extractor/1.0 (research)"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            dest.write_bytes(resp.read())
    except Exception as exc:
        log.error("Download failed: %s", exc)
        return False

    log.info("Saved %s (%d bytes)", dest, dest.stat().st_size)
    return True


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------


def _load_ideal_points(path: Path) -> list[dict]:
    """Parse Idealpoints.tab and return list of {ccode, year, ideal_point, se, country}."""
    rows = []
    with path.open(newline="", encoding="utf-8-sig") as fh:
        # The file uses tabs as delimiters; Python csv handles both tab and comma.
        dialect = "excel-tab" if "\t" in fh.readline() else "excel"
        fh.seek(0)
        reader = csv.DictReader(fh, dialect=dialect)
        for row in reader:
            # Normalise column name variants across BSV dataset versions
            ideal_raw = (
                row.get("Idealpoint")
                or row.get("IdealPoint")
                or row.get("idealpoint")
                or ""
            ).strip()
            se_raw = (row.get("se") or row.get("SE") or "").strip()
            year_raw = (row.get("year") or row.get("Year") or "").strip()
            ccode_raw = (row.get("ccode") or row.get("Ccode") or "").strip()
            country_raw = (
                row.get("Country")
                or row.get("country")
                or row.get("countryname")
                or ""
            ).strip()

            if not ideal_raw or not year_raw:
                continue
            try:
                rows.append({
                    "ccode": int(ccode_raw) if ccode_raw.isdigit() else None,
                    "year": int(year_raw),
                    "ideal_point": float(ideal_raw),
                    "se": float(se_raw) if se_raw else None,
                    "country": country_raw,
                })
            except ValueError:
                continue
    return rows


# ---------------------------------------------------------------------------
# Country matching
# ---------------------------------------------------------------------------


def _build_name_to_iso3(session: Session) -> dict[str, str]:
    """Return {normalized_name: iso3} for all countries in the DB."""
    rows = session.execute(
        text("SELECT name, short_name, iso3 FROM countries WHERE iso3 IS NOT NULL")
    ).fetchall()
    mapping: dict[str, str] = {}
    for name, short_name, iso3 in rows:
        for n in (name, short_name):
            if n:
                mapping[normalize_country_name(n)] = iso3
    return mapping


def _build_iso3_to_country_id(session: Session) -> dict[str, int]:
    rows = session.execute(
        text("SELECT iso3, id FROM countries WHERE iso3 IS NOT NULL")
    ).fetchall()
    return {iso3.upper(): cid for iso3, cid in rows}


def _resolve_iso3(
    ccode: int | None,
    country: str,
    name_to_iso3: dict[str, str],
) -> str | None:
    # 1. Direct COW lookup
    if ccode is not None:
        iso3 = _COW_TO_ISO3.get(ccode)
        if iso3:
            return iso3

    # 2. Normalised country name
    if country:
        key = normalize_country_name(country)
        iso3 = name_to_iso3.get(key)
        if iso3:
            return iso3

    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def import_voeten_ideal_points(
    db_url: str | None = None,
    file_path: Path | None = None,
    force_download: bool = False,
    dry_run: bool = False,
) -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if file_path is None:
        file_path = _IDEAL_POINTS_FILE
        if not _download_ideal_points(file_path, force=force_download):
            sys.exit(1)

    rows = _load_ideal_points(file_path)
    log.info("Parsed %d (country, year) rows from %s", len(rows), file_path.name)

    engine = get_engine(db_url)

    with get_session(engine) as session:
        _ensure_schema(session)
        name_to_iso3 = _build_name_to_iso3(session)
        iso3_to_country_id = _build_iso3_to_country_id(session)

    unmatched: list[tuple[int | None, str]] = []
    matched = skipped = 0

    with get_session(engine) as session:
        for row in rows:
            iso3 = _resolve_iso3(row["ccode"], row["country"], name_to_iso3)
            if iso3 is None:
                unmatched.append((row["ccode"], row["country"]))
                skipped += 1
                continue

            country_id = iso3_to_country_id.get(iso3.upper())

            if not dry_run:
                session.execute(
                    text(
                        """
                        INSERT INTO country_ideal_points
                            (country_id, iso3, year, ideal_point, se, source)
                        VALUES (:cid, :iso3, :year, :ip, :se, 'voeten_bsv2017')
                        ON CONFLICT (iso3, year) DO UPDATE
                            SET ideal_point = EXCLUDED.ideal_point,
                                se          = EXCLUDED.se,
                                source      = EXCLUDED.source,
                                country_id  = EXCLUDED.country_id
                        """
                    ),
                    {
                        "cid": country_id,
                        "iso3": iso3,
                        "year": row["year"],
                        "ip": row["ideal_point"],
                        "se": row["se"],
                    },
                )
            matched += 1

        if not dry_run:
            session.commit()

    action = "Would upsert" if dry_run else "Upserted"
    log.info("%s %d rows; %d rows skipped (no country match).", action, matched, skipped)

    if unmatched:
        unique_unmatched = sorted({f"ccode={c} name={n!r}" for c, n in unmatched})
        log.warning(
            "%d distinct unmatched countries:\n  %s",
            len(unique_unmatched),
            "\n  ".join(unique_unmatched[:30]),
        )

    if not dry_run:
        with get_session(engine) as session:
            stats = session.execute(
                text(
                    """
                    SELECT
                        min(year), max(year), count(*), count(DISTINCT iso3)
                    FROM country_ideal_points
                    WHERE source = 'voeten_bsv2017'
                    """
                )
            ).fetchone()
            log.info(
                "DB totals (voeten_bsv2017): years %s–%s | %s rows | %s countries",
                *stats,
            )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    p = argparse.ArgumentParser(
        description="Import Voeten/BSV ideal points into country_ideal_points.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument(
        "--file",
        default=None,
        metavar="PATH",
        help="Path to Idealpoints.tab (skips download)",
    )
    p.add_argument(
        "--download",
        action="store_true",
        help="Force re-download even if cached file exists",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and match without writing to the database",
    )
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    import_voeten_ideal_points(
        db_url=args.db,
        file_path=Path(args.file) if args.file else None,
        force_download=args.download,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
