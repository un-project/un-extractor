#!/usr/bin/env python3
"""Send pg_notify('un_data_updated', payload) to wake the un-project.org listener.

The un-project.org listener container watches this channel and responds by
calling refresh_search_index and clearing the shared DatabaseCache so all
Gunicorn workers serve fresh results without a restart.

Usage
-----
    python scripts/notify_update.py --db postgresql://user:pass@host/db
    python scripts/notify_update.py --payload votes_only
    DATABASE_URL=postgresql://... python scripts/notify_update.py
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import psycopg2  # noqa: E402

log = logging.getLogger(__name__)

_CHANNEL = "un_data_updated"
_DEFAULT_PAYLOAD = "ingest_complete"


def notify(db_url: str, payload: str) -> None:
    conn = psycopg2.connect(db_url)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SELECT pg_notify(%s, %s)", (_CHANNEL, payload))
        log.info("NOTIFY %s '%s' sent.", _CHANNEL, payload)
    finally:
        conn.close()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--db", default=os.environ.get("DATABASE_URL"),
                   help="PostgreSQL connection URL (default: $DATABASE_URL)")
    p.add_argument("--payload", default=_DEFAULT_PAYLOAD,
                   help=f"NOTIFY payload string (default: {_DEFAULT_PAYLOAD!r})")
    args = p.parse_args()

    if not args.db:
        p.error("--db or $DATABASE_URL is required")

    try:
        notify(args.db, args.payload)
    except psycopg2.OperationalError as exc:
        log.error("Could not connect to database: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
