"""Single-PDF processing pipeline.

Orchestrates all six phases for one PDF:

    Phase 1 – PDF ingestion (extract_pages → clean_pages)
    Phase 2 – Structure detection (detect_sections)
    Phase 3 – Rule-based extraction (metadata, speeches, votes)
    Phase 4 – LLM semantic extraction (optional, can be disabled)
    Phase 5 – JSON validation (validate_record)
    Phase 6 – Output to JSON file

Usage
-----
    from src.pipeline.process_pdf import process_pdf
    record = process_pdf(Path("data/raw_pdfs/en/ga/64/pv/document_121.pdf"))
"""

from __future__ import annotations

import logging
from datetime import date
from pathlib import Path
from typing import Any

from src.extraction.metadata_extractor import extract_all as extract_metadata
from src.extraction.speaker_extractor import extract_speeches
from src.extraction.vote_extractor import extract_votes_and_directions
from src.models import AgendaItem, MeetingRecord, PresidentInfo
from src.pdf.clean_text import clean_pages, flatten_blocks
from src.pdf.extract_text import extract_pages
from src.structure.detect_sections import Section, detect_sections
from src.validation.json_validator import validate_record

log = logging.getLogger(__name__)


class ExtractionError(Exception):
    """Raised when a PDF cannot be processed."""

    def __init__(self, pdf_path: Path, phase: str, cause: Exception) -> None:
        super().__init__(f"[{phase}] {pdf_path}: {cause}")
        self.pdf_path = pdf_path
        self.phase = phase
        self.cause = cause


# ---------------------------------------------------------------------------
# Agenda item extraction (from agenda_item sections)
# ---------------------------------------------------------------------------


def _extract_agenda_items(sections: list[Section]) -> list[AgendaItem]:
    """Build ``AgendaItem`` objects from ``agenda_item`` sections."""
    import re

    _AGENDA_RE = re.compile(
        r"Agenda\s+items?\s+(\d+)(?:\s+(?:and|to)\s+\d+)?"
        r"(?:\s+\(continued\))?"
        r"\s*(.*)",
        re.IGNORECASE | re.DOTALL,
    )
    _SUB_ITEM_RE = re.compile(r"^\(([a-z])\)\s+(.*)", re.IGNORECASE | re.DOTALL)

    items: list[AgendaItem] = []
    for sec in sections:
        if sec.section_type != "agenda_item":
            continue
        text = sec.text.strip()
        m = _AGENDA_RE.search(text)
        if not m:
            continue
        number = int(m.group(1))
        rest = m.group(2).strip() if m.group(2) else ""

        continued = "(continued)" in text.lower()
        sub_item: str | None = None

        # Check for sub-item label on a subsequent block
        for block in sec.blocks[1:]:
            sm = _SUB_ITEM_RE.match(block.text.strip())
            if sm:
                sub_item = sm.group(1).lower()
                title_text = sm.group(2).strip()
                rest = title_text if title_text else rest
                break

        title = rest.replace("(continued)", "").strip() or "—"
        items.append(
            AgendaItem(
                number=number,
                sub_item=sub_item,
                title=title,
                continued=continued,
            )
        )
    return items


# ---------------------------------------------------------------------------
# Main pipeline function
# ---------------------------------------------------------------------------


def process_pdf(
    pdf_path: Path,
    output_dir: Path | None = None,
    use_llm: bool = False,
    llm_api_key: str | None = None,
) -> MeetingRecord:
    """Process one PDF through the full pipeline.

    Parameters
    ----------
    pdf_path:
        Path to the source PDF.
    output_dir:
        If given, the resulting JSON is written to
        ``output_dir/meeting_{sanitised_symbol}.json``.
    use_llm:
        When ``True``, call the Claude API for semantic enrichment.
        Requires ``ANTHROPIC_API_KEY`` or *llm_api_key*.
    llm_api_key:
        Optional explicit API key (overrides environment variable).

    Returns
    -------
    MeetingRecord
        The fully extracted and validated meeting record.

    Raises
    ------
    ExtractionError
        If any pipeline phase fails.
    """
    log.info("Processing %s", pdf_path)

    # --- Phase 1: PDF ingestion ------------------------------------------------
    try:
        raw_pages = extract_pages(pdf_path)
        clean = clean_pages(raw_pages)
        blocks = flatten_blocks(clean)
    except Exception as exc:
        raise ExtractionError(pdf_path, "pdf_ingestion", exc) from exc

    # --- Phase 2: Structure detection ------------------------------------------
    try:
        sections = detect_sections(blocks)
    except Exception as exc:
        raise ExtractionError(pdf_path, "structure_detection", exc) from exc

    # --- Phase 3: Rule-based extraction ----------------------------------------
    try:
        cover_blocks = [
            b for s in sections if s.section_type == "cover" for b in s.blocks
        ]
        meta: dict[str, Any] = extract_metadata(cover_blocks)

        speeches = extract_speeches(sections)
        resolutions, stage_directions = extract_votes_and_directions(sections)
        agenda_items = _extract_agenda_items(sections)
    except Exception as exc:
        raise ExtractionError(pdf_path, "rule_based_extraction", exc) from exc

    # Build adoption context map for resolution title extraction.
    # Maps draft_symbol -> text of the adoption section + ~8 preceding sections.
    _adoption_context: dict[str, str] = {}
    for _i, _sec in enumerate(sections):
        if (
            _sec.section_type == "stage_direction"
            and "was adopted" in _sec.text.lower()
        ):
            _ctx_start = max(0, _i - 8)
            _ctx = "\n".join(s.text for s in sections[_ctx_start : _i + 1])
            for _res in resolutions:
                if (
                    _res.draft_symbol in _sec.text
                    and _res.draft_symbol not in _adoption_context
                ):
                    _adoption_context[_res.draft_symbol] = _ctx

    # --- Phase 4: LLM semantic enrichment (optional) ---------------------------
    if use_llm:
        try:
            from src.llm.semantic_extractor import SemanticExtractor

            llm = SemanticExtractor(api_key=llm_api_key)

            # Enrich on_behalf_of for speeches that don't have it yet
            for i, speech in enumerate(speeches):
                if not speech.speaker.on_behalf_of and speech.text:
                    group = llm.extract_group_affiliation(speech.text[:500])
                    if group:
                        speeches[i] = speech.model_copy(
                            update={
                                "speaker": speech.speaker.model_copy(
                                    update={"on_behalf_of": group}
                                )
                            }
                        )

            # Normalise country names in country votes
            for res in resolutions:
                if res.country_votes:
                    raw_names = list({cv.country for cv in res.country_votes})
                    norm_map = llm.normalise_countries(raw_names)
                    res.country_votes = [
                        cv.model_copy(
                            update={"country": norm_map.get(cv.country) or cv.country}
                        )
                        for cv in res.country_votes
                    ]

            # Extract resolution titles from surrounding document context
            for res in resolutions:
                if not res.title and res.draft_symbol in _adoption_context:
                    title = llm.extract_resolution_title(
                        res.draft_symbol, _adoption_context[res.draft_symbol]
                    )
                    if title:
                        res.title = title

        except Exception as exc:
            log.warning("LLM enrichment failed for %s: %s", pdf_path, exc)
            # Non-fatal: continue without LLM enrichment

    # --- Phase 5: Assemble and validate ----------------------------------------
    try:
        symbol: str = meta.get("symbol") or ""
        session_num: int = int(meta.get("session") or 0)
        meeting_num: int = int(meta.get("meeting_number") or 0)
        doc_date: date | None = meta.get("date")
        if doc_date is None:
            log.warning(
                "Date not found in %s — defaulting to 1900-01-01", pdf_path.name
            )
        location: str = meta.get("location") or ""
        president: PresidentInfo | None = meta.get("president")
        body: str = meta.get("body") or "GA"

        record = MeetingRecord(
            symbol=symbol,
            body=body,
            session=session_num,
            meeting_number=meeting_num,
            date=doc_date or date(1900, 1, 1),
            location=location,
            president=president,
            agenda_items=agenda_items,
            speeches=speeches,
            stage_directions=stage_directions,
            resolutions=resolutions,
        )

        errors = validate_record(record)
        if errors:
            for err in errors:
                log.warning("Validation: %s — %s", pdf_path.name, err)
    except Exception as exc:
        raise ExtractionError(pdf_path, "validation", exc) from exc

    # --- Phase 6: Write JSON ---------------------------------------------------
    if output_dir is not None:
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            safe_symbol = record.symbol.replace("/", "_")
            out_path = output_dir / f"meeting_{safe_symbol}.json"
            with out_path.open("w", encoding="utf-8") as fh:
                fh.write(record.model_dump_json(indent=2))
            log.info("Written → %s", out_path)
        except Exception as exc:
            log.error("Failed to write output for %s: %s", pdf_path, exc)

    return record
