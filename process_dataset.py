#!/usr/bin/env python3
"""CLI: process a directory of UN meeting PDFs.

Usage
-----
    python process_dataset.py data/raw_pdfs/
    python process_dataset.py data/raw_pdfs/ --output output/ --workers 8
    python process_dataset.py data/raw_pdfs/ --llm
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from src.pipeline.batch_processor import process_batch


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Process UN meeting PDFs into structured JSON.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("root_dir", type=Path, help="Root directory containing PDFs")
    p.add_argument(
        "--output",
        type=Path,
        default=Path("output"),
        help="Directory for JSON output files",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Number of parallel worker threads",
    )
    p.add_argument(
        "--llm",
        action="store_true",
        default=False,
        help="Enable Claude API semantic enrichment (requires ANTHROPIC_API_KEY)",
    )
    p.add_argument(
        "--api-key",
        default=None,
        help="Anthropic API key (overrides ANTHROPIC_API_KEY env var)",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable debug logging",
    )
    return p


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.root_dir.exists():
        print(f"Error: {args.root_dir} does not exist", file=sys.stderr)
        return 1

    summary = process_batch(
        root_dir=args.root_dir,
        output_dir=args.output,
        max_workers=args.workers,
        use_llm=args.llm,
        llm_api_key=args.api_key,
    )

    print(
        f"\nDone: {summary.succeeded}/{summary.total} succeeded "
        f"({summary.success_rate:.1%})"
    )
    if summary.failed:
        print(f"  {summary.failed} failed — see output/failed/ for error reports")
    return 0 if summary.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
