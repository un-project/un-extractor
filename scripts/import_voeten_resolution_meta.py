#!/usr/bin/env python3
"""Import Voeten resolution-level metadata: importantvote flag and issue area codes.

Downloads two CSV files from the TidyTuesday / unvotes package (Erik Voeten,
Anton Strezhnev, Michael Bailey):

  roll_calls.csv  — per-vote metadata including the ``importantvote`` binary flag
  issues.csv      — per-vote issue-area codes (me, nu, co, hr, ec, di)

Coverage: 6,202 GA roll-call votes, 1946–2019.

Schema changes (applied automatically if columns are absent):

  resolutions.important_vote  BOOLEAN   -- Voeten "important vote" coding
  resolutions.issue_me        BOOLEAN   -- Palestinian conflict
  resolutions.issue_nu        BOOLEAN   -- Nuclear weapons / material
  resolutions.issue_co        BOOLEAN   -- Colonialism
  resolutions.issue_hr        BOOLEAN   -- Human rights
  resolutions.issue_ec        BOOLEAN   -- Economic development
  resolutions.issue_di        BOOLEAN   -- Arms control / disarmament

All new columns default to NULL (= not coded / unknown).

Matching: ``unres`` in the CSV is normalised to both long form
(``A/RES/57/60``) and short form (``57/60``) and matched against
``resolutions.adopted_symbol``.

Usage
-----
    python scripts/import_voeten_resolution_meta.py
    python scripts/import_voeten_resolution_meta.py --db postgresql://...
    python scripts/import_voeten_resolution_meta.py --download
    python scripts/import_voeten_resolution_meta.py --dry-run
    python scripts/import_voeten_resolution_meta.py --verbose

Source
------
  Voeten, E., Strezhnev, A., & Bailey, M. (2009).
  United Nations General Assembly Voting Data. Harvard Dataverse.
  Accessed via the unvotes R package (Robinson et al.) /
  TidyTuesday 2021-03-23 release. CC0.
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
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import get_engine, get_session  # noqa: E402

log = logging.getLogger(__name__)

_CACHE_DIR = Path(__file__).resolve().parents[1] / "data" / "voeten"
_ROLL_CALLS_FILE = _CACHE_DIR / "roll_calls.csv"
_ISSUES_FILE = _CACHE_DIR / "issues.csv"

_ROLL_CALLS_URL = (
    "https://raw.githubusercontent.com/rfordatascience/tidytuesday"
    "/master/data/2021/2021-03-23/roll_calls.csv"
)
_ISSUES_URL = (
    "https://raw.githubusercontent.com/rfordatascience/tidytuesday"
    "/master/data/2021/2021-03-23/issues.csv"
)

_ISSUE_COLS = ("me", "nu", "co", "hr", "ec", "di")


# ---------------------------------------------------------------------------
# Schema migration
# ---------------------------------------------------------------------------


def _ensure_columns(session: Session) -> None:
    """Add new columns to resolutions if they don't already exist."""
    new_cols = [
        ("important_vote", "BOOLEAN"),
        ("issue_me", "BOOLEAN"),
        ("issue_nu", "BOOLEAN"),
        ("issue_co", "BOOLEAN"),
        ("issue_hr", "BOOLEAN"),
        ("issue_ec", "BOOLEAN"),
        ("issue_di", "BOOLEAN"),
    ]
    existing = {
        row[0]
        for row in session.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'resolutions'"
            )
        ).fetchall()
    }
    for col, typ in new_cols:
        if col not in existing:
            session.execute(
                text(f"ALTER TABLE resolutions ADD COLUMN {col} {typ}")
            )
            log.info("Added column resolutions.%s", col)
    session.commit()


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


def _download_file(url: str, dest: Path, force: bool) -> Path:
    if dest.exists() and not force:
        log.info("Using cached %s", dest.name)
        return dest
    log.info("Downloading %s …", dest.name)
    req = urllib.request.Request(
        url, headers={"User-Agent": "un-extractor/1.0 (research)"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        dest.write_bytes(resp.read())
    log.info("Saved %s", dest)
    return dest


# ---------------------------------------------------------------------------
# Parse CSV files
# ---------------------------------------------------------------------------


def _normalise_unres(unres: str) -> list[str]:
    """Return candidate adopted_symbol values to try for a given unres string.

    unres formats:
      "R/57/60"      → short form "57/60" and long form "A/RES/57/60"
      "A/RES/71/5"   → long form "A/RES/71/5" and short form "71/5"
    """
    s = unres.strip()
    if s.startswith("A/RES/"):
        short = s[len("A/RES/"):]
        return [s, short]
    if s.startswith("R/"):
        short = s[2:]
        return [short, f"A/RES/{short}"]
    return [s]


def _load_roll_calls(path: Path) -> dict[str, dict[str, str]]:
    """Return {rcid: {importantvote, unres, session}} keyed by rcid string."""
    result: dict[str, dict[str, str]] = {}
    with path.open(newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            rcid = row.get("rcid", "").strip()
            if rcid:
                result[rcid] = {
                    "importantvote": row.get("importantvote", "").strip(),
                    "unres": row.get("unres", "").strip(),
                    "session": row.get("session", "").strip(),
                }
    return result


def _load_issues(path: Path) -> dict[str, set[str]]:
    """Return {rcid: {short_name, ...}} from issues.csv."""
    result: dict[str, set[str]] = {}
    with path.open(newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            rcid = row.get("rcid", "").strip()
            short = row.get("short_name", "").strip()
            if rcid and short:
                result.setdefault(rcid, set()).add(short)
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def import_voeten_resolution_meta(
    db_url: str | None = None,
    force_download: bool = False,
    dry_run: bool = False,
) -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _download_file(_ROLL_CALLS_URL, _ROLL_CALLS_FILE, force_download)
    _download_file(_ISSUES_URL, _ISSUES_FILE, force_download)

    roll_calls = _load_roll_calls(_ROLL_CALLS_FILE)
    issues = _load_issues(_ISSUES_FILE)
    log.info(
        "Loaded %d roll calls, %d with issue codes.",
        len(roll_calls),
        len(issues),
    )

    engine = get_engine(db_url)

    with get_session(engine) as session:
        _ensure_columns(session)

        # Build symbol → resolution_id lookup (both long and short forms)
        rows = session.execute(
            text(
                "SELECT id, adopted_symbol FROM resolutions "
                "WHERE body = 'GA' AND adopted_symbol IS NOT NULL"
            )
        ).fetchall()
        symbol_to_id: dict[str, int] = {sym: rid for rid, sym in rows}
        log.info("Loaded %d GA resolution symbols from DB.", len(symbol_to_id))

    updated = unmatched = 0

    with get_session(engine) as session:
        for rcid, rc in roll_calls.items():
            unres = rc["unres"]
            if not unres:
                unmatched += 1
                continue

            res_id = None
            for candidate in _normalise_unres(unres):
                res_id = symbol_to_id.get(candidate)
                if res_id:
                    break

            if res_id is None:
                log.debug("No DB match for rcid=%s unres=%s", rcid, unres)
                unmatched += 1
                continue

            important = rc["importantvote"] == "1"
            rcid_issues = issues.get(rcid, set())

            params: dict[str, object] = {
                "id": res_id,
                "important_vote": important,
                "issue_me": "me" in rcid_issues,
                "issue_nu": "nu" in rcid_issues,
                "issue_co": "co" in rcid_issues,
                "issue_hr": "hr" in rcid_issues,
                "issue_ec": "ec" in rcid_issues,
                "issue_di": "di" in rcid_issues,
            }

            log.debug(
                "rcid=%s unres=%s res_id=%d important=%s issues=%s",
                rcid, unres, res_id, important, rcid_issues,
            )

            if not dry_run:
                session.execute(
                    text(
                        """
                        UPDATE resolutions SET
                            important_vote = :important_vote,
                            issue_me = :issue_me,
                            issue_nu = :issue_nu,
                            issue_co = :issue_co,
                            issue_hr = :issue_hr,
                            issue_ec = :issue_ec,
                            issue_di = :issue_di
                        WHERE id = :id
                        """
                    ),
                    params,
                )
            updated += 1

        if not dry_run:
            session.commit()

    action = "Would update" if dry_run else "Updated"
    log.info(
        "%s %d resolutions; %d roll calls had no DB match.",
        action, updated, unmatched,
    )

    if not dry_run:
        with get_session(engine) as session:
            stats = session.execute(
                text(
                    """
                    SELECT
                        count(*) FILTER (WHERE important_vote = true)  AS important,
                        count(*) FILTER (WHERE issue_me = true)        AS me,
                        count(*) FILTER (WHERE issue_nu = true)        AS nu,
                        count(*) FILTER (WHERE issue_co = true)        AS co,
                        count(*) FILTER (WHERE issue_hr = true)        AS hr,
                        count(*) FILTER (WHERE issue_ec = true)        AS ec,
                        count(*) FILTER (WHERE issue_di = true)        AS di
                    FROM resolutions WHERE body = 'GA'
                    """
                )
            ).fetchone()
            log.info(
                "DB totals — important: %d | me: %d | nu: %d | co: %d | "
                "hr: %d | ec: %d | di: %d",
                *stats,
            )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Import Voeten importantvote flag and issue area codes "
            "into resolutions table."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument(
        "--download",
        action="store_true",
        help="Force re-download even if cached files exist",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Match and log without writing to the database",
    )
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    import_voeten_resolution_meta(
        db_url=args.db,
        force_download=args.download,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
