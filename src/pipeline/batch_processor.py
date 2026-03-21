"""Parallel batch processing of UN meeting PDFs.

Processes all PDFs found under a root directory using a thread pool.
Failed PDFs are logged and written to ``output/failed/`` for manual review.

Usage
-----
    from src.pipeline.batch_processor import process_batch
    results = process_batch(
        root_dir=Path("data/raw_pdfs"),
        output_dir=Path("output"),
        max_workers=8,
    )
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator

from src.models import MeetingRecord
from src.pipeline.process_pdf import ExtractionError, process_pdf

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class ProcessResult:
    pdf_path: Path
    success: bool
    record: MeetingRecord | None = None
    error: str | None = None
    phase: str | None = None


@dataclass
class BatchSummary:
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    results: list[ProcessResult] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        return self.succeeded / self.total if self.total else 0.0


# ---------------------------------------------------------------------------
# PDF discovery
# ---------------------------------------------------------------------------


def find_pdfs(root_dir: Path) -> list[Path]:
    """Return all PDF files under *root_dir* sorted by path.

    Folders named ``res`` (UN General Assembly resolutions) are excluded
    because they are not verbatim meeting records and cannot be processed
    by this pipeline.
    """
    return sorted(p for p in root_dir.rglob("*.pdf") if p.parent.name != "res")


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------


def _process_one(
    pdf_path: Path,
    output_dir: Path,
    use_llm: bool,
    llm_api_key: str | None,
    debug_dir: Path | None = None,
) -> ProcessResult:
    try:
        record = process_pdf(
            pdf_path,
            output_dir=output_dir,
            use_llm=use_llm,
            llm_api_key=llm_api_key,
            debug_dir=debug_dir,
        )
        return ProcessResult(pdf_path=pdf_path, success=True, record=record)
    except ExtractionError as exc:
        return ProcessResult(
            pdf_path=pdf_path,
            success=False,
            error=str(exc.cause),
            phase=exc.phase,
        )
    except Exception as exc:
        return ProcessResult(
            pdf_path=pdf_path,
            success=False,
            error=str(exc),
            phase="unknown",
        )


def _write_failure_report(
    result: ProcessResult,
    failed_dir: Path,
    root_dir: Path | None = None,
) -> None:
    """Write a JSON failure report for a failed PDF."""
    failed_dir.mkdir(parents=True, exist_ok=True)
    try:
        rel = result.pdf_path.relative_to(root_dir) if root_dir else None
    except ValueError:
        rel = None
    safe_name = (
        rel.with_suffix("").as_posix().replace("/", "_")
        if rel is not None
        else result.pdf_path.stem
    )
    report = {
        "pdf_path": str(result.pdf_path),
        "phase": result.phase,
        "error": result.error,
        "timestamp": datetime.utcnow().isoformat(),
    }
    out_path = failed_dir / f"{safe_name}_error.json"
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)


# ---------------------------------------------------------------------------
# Batch entry point
# ---------------------------------------------------------------------------


def process_batch(
    root_dir: Path,
    output_dir: Path,
    max_workers: int = 8,
    use_llm: bool = False,
    llm_api_key: str | None = None,
    pdf_paths: list[Path] | None = None,
    debug: bool = False,
) -> BatchSummary:
    """Process all PDFs under *root_dir* in parallel.

    Parameters
    ----------
    root_dir:
        Root directory to search for PDFs (ignored if *pdf_paths* is given).
    output_dir:
        Directory for JSON output files.
    max_workers:
        Number of parallel threads.
    use_llm:
        Enable Claude API semantic enrichment.
    llm_api_key:
        Optional explicit API key.
    pdf_paths:
        Explicit list of PDFs to process (skips discovery).

    Returns
    -------
    BatchSummary
        Counts and individual results.
    """
    pdfs = pdf_paths if pdf_paths is not None else find_pdfs(root_dir)
    failed_dir = output_dir / "failed"
    debug_dir = output_dir / "debug" if debug else None
    summary = BatchSummary(total=len(pdfs))

    log.info("Starting batch: %d PDFs, %d workers", len(pdfs), max_workers)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                _process_one, pdf, output_dir, use_llm, llm_api_key, debug_dir
            ): pdf
            for pdf in pdfs
        }
        for future in as_completed(futures):
            result = future.result()
            summary.results.append(result)
            if result.success:
                summary.succeeded += 1
                log.info("✓ %s", result.pdf_path.name)
            else:
                summary.failed += 1
                log.warning(
                    "✗ %s [%s]: %s", result.pdf_path.name, result.phase, result.error
                )
                _write_failure_report(result, failed_dir, root_dir)

    log.info(
        "Batch complete: %d/%d succeeded (%.1f%%)",
        summary.succeeded,
        summary.total,
        summary.success_rate * 100,
    )
    return summary


def iter_records(root_dir: Path) -> Iterator[MeetingRecord]:
    """Yield successfully extracted records one at a time (no parallelism).

    Useful for memory-constrained imports where you process one PDF,
    import it to the DB, and discard the record before loading the next.
    """
    for pdf_path in find_pdfs(root_dir):
        try:
            yield process_pdf(pdf_path)
        except ExtractionError as exc:
            log.warning("Skipping %s: %s", pdf_path.name, exc)
