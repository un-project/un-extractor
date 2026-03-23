"""Single-PDF processing pipeline.

Orchestrates all six phases for one PDF:

    Phase 1 – PDF ingestion (extract_pages → clean_pages)
    Phase 2 – Structure detection (detect_sections)
    Phase 3 – Metadata extraction + item grouping
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
import re
from datetime import date
from pathlib import Path
from typing import Any

from src.extraction.metadata_extractor import extract_all as extract_metadata
from src.extraction.speaker_extractor import extract_speech
from src.extraction.vote_extractor import (
    extract_resolution_from_adoption,
    extract_resolution_title,
    extract_stage_direction,
)
from src.models import DocumentItem, MeetingRecord, PresidentInfo, TextBlock
from src.pdf.clean_text import clean_pages, flatten_blocks, normalize_allcaps
from src.pdf.extract_text import extract_pages
from src.structure.detect_sections import Section, detect_sections
from src.validation.json_validator import validate_record

log = logging.getLogger(__name__)


def _session_from_path(pdf_path: Path) -> int | None:
    """Extract the GA/SC session number from the directory structure.

    Expects a path component pattern like ``…/{session}/pv/…`` where
    ``{session}`` is a plain integer (e.g. 31).  Returns ``None`` if the
    pattern is not found.
    """
    parts = pdf_path.parts
    for name in ("pv", "res"):
        if name in parts:
            idx = parts.index(name)
            candidate = parts[idx - 1]
            if candidate.isdigit():
                return int(candidate)
    return None


# ---------------------------------------------------------------------------
# Agenda header parsing
# ---------------------------------------------------------------------------

_AGENDA_NUM_RE = re.compile(
    r"Agenda\s+items?\s+(\d+)(?:\s+(?:and|to)\s+\d+)?(?:\s+\(continued\))?",
    re.IGNORECASE,
)
_SUB_ITEM_RE = re.compile(r"^\(([a-z])\)\s+(.*)", re.IGNORECASE | re.DOTALL)


def _parse_agenda_header(text: str) -> tuple[int | None, str | None, bool, str]:
    """Return (number, sub_item, continued, title) from an agenda section text."""
    m = _AGENDA_NUM_RE.search(text)
    if not m:
        return None, None, False, text.strip()
    number = int(m.group(1))
    continued = "(continued)" in text.lower()
    after = text[m.end() :].strip()
    sm = _SUB_ITEM_RE.match(after)
    if sm:
        sub_item: str | None = sm.group(1).lower()
        title = sm.group(2).strip()
    else:
        sub_item = None
        title = after or "—"
    title = normalize_allcaps(title.replace("(continued)", "").strip() or "—")
    return number, sub_item, continued, title


# ---------------------------------------------------------------------------
# Core grouping: sections → DocumentItems
# ---------------------------------------------------------------------------


def _group_into_items(sections: list[Section]) -> list[DocumentItem]:
    """Walk sections in document order and group them into DocumentItems.

    Each DocumentItem collects its speeches, stage_directions, and resolutions
    with a shared ``position_in_item`` counter so the full document can be
    reconstructed by merging all three lists sorted by that field.

    Adoption lines embedded in speaker turns or agenda_item sections
    (e.g. when the President reads out vote tallies) are detected and
    extracted alongside the normal stage-direction adoptions.
    """
    # Pre-compute per-section block offsets for fast "following blocks" lookups.
    all_blocks = [b for sec in sections for b in sec.blocks]
    sec_offset: dict[int, int] = {}
    running = 0
    for sec in sections:
        sec_offset[id(sec)] = running
        running += len(sec.blocks)

    def _following(sec: Section, n: int = 80) -> list[TextBlock]:
        start = sec_offset[id(sec)] + len(sec.blocks)
        return all_blocks[start : start + n]

    items: list[DocumentItem] = []
    current: DocumentItem | None = None
    global_pos = 0  # document-wide speech/stage-direction counter
    elem_pos = 0  # position within the current item (shared across types)

    # Track draft_symbols already added to current item to avoid duplicates
    # when adoption text appears in both an agenda_item/speaker_turn section
    # and a following stage_direction section.
    current_item_symbols: set[str] = set()

    # For the newer recorded-vote format the country lists appear *before*
    # the adoption line.  We buffer body blocks that follow a "recorded vote
    # taken" signal so they can be passed as context when the adoption line
    # is encountered later.
    _pending_vote_blocks: list[TextBlock] = (
        []
    )  # accumulated body blocks after vote signal
    _after_vote_signal: bool = False  # True after "A recorded vote was taken."

    # Track the most recent resolution_header text so adoption lines that
    # carry no draft symbol ("The draft resolution was adopted.") can look up
    # the symbol from the preceding bold header block.
    _last_resolution_header_text: str = ""

    def _flush_and_start(
        title: str,
        item_type: str,
        agenda_number: int | None = None,
        sub_item: str | None = None,
        continued: bool = False,
    ) -> None:
        nonlocal current, elem_pos, current_item_symbols, _last_resolution_header_text
        if current is not None:
            items.append(current)
        current = DocumentItem(
            position=len(items),
            item_type=item_type,
            title=title,
            agenda_number=agenda_number,
            sub_item=sub_item,
            continued=continued,
        )
        elem_pos = 0
        current_item_symbols = set()
        _last_resolution_header_text = ""

    def _try_add_resolution(
        sec: Section,
        extra_blocks: list[TextBlock] | None = None,
        preceding_text: str = "",
    ) -> None:
        """Extract and append a resolution if an adoption line is found."""
        nonlocal elem_pos
        if current is None:
            return
        context_blocks = list(sec.blocks) + (extra_blocks or [])
        res = extract_resolution_from_adoption(sec.text, context_blocks, preceding_text)
        if res is not None and res.draft_symbol not in current_item_symbols:
            current.resolutions.append(
                res.model_copy(update={"position_in_item": elem_pos})
            )
            current_item_symbols.add(res.draft_symbol)
            elem_pos += 1

    for section in sections:
        if section.section_type == "cover":
            continue

        # ---- Agenda item boundary ------------------------------------------------
        if section.section_type == "agenda_item":
            number, sub_item, continued, title = _parse_agenda_header(section.text)
            _flush_and_start(
                title=title,
                item_type="agenda_item",
                agenda_number=number,
                sub_item=sub_item,
                continued=continued,
            )
            # Adoptions sometimes appear inside the agenda_item section itself
            # (e.g. document_107 where L.68 adoption is in the same block).
            _try_add_resolution(section, _following(section))
            continue

        # Ensure there is always a current item before adding content.
        if current is None:
            _flush_and_start(title="", item_type="other_item")

        # ---- Speaker turn --------------------------------------------------------
        if section.section_type == "speaker_turn":
            # Save any buffered vote blocks before clearing (SC: the adoption
            # announcement is in a speech that follows the country lists).
            saved_pending = _pending_vote_blocks if _after_vote_signal else []
            # A new speaker resets any pending recorded-vote state so country
            # lists from one vote don't leak into a later resolution.
            _after_vote_signal = False
            _pending_vote_blocks = []
            speech = extract_speech(section, global_pos)
            if speech is not None and current is not None:
                current.speeches.append(
                    speech.model_copy(update={"position_in_item": elem_pos})
                )
                elem_pos += 1
            global_pos += 1
            # Adoption lines embedded in a speaker turn (e.g. The President
            # reading recorded-vote results aloud, as in document_107 L.67).
            # For SC, the country lists are already in saved_pending; do not
            # append _following(section) or speech text from later delegates
            # leaks into the "Abstaining" section via the country-vote parser.
            # For GA, saved_pending is empty so we fall back to following blocks.
            surrounding = saved_pending if saved_pending else _following(section)
            if not _last_resolution_header_text and current is not None:
                speech_context = " ".join(s.text for s in current.speeches[-5:])
            else:
                speech_context = ""
            _try_add_resolution(
                section,
                surrounding,
                _last_resolution_header_text or speech_context,
            )

        # ---- Stage direction -----------------------------------------------------
        elif section.section_type == "stage_direction":
            sd = extract_stage_direction(section, global_pos)
            if current is not None:
                current.stage_directions.append(
                    sd.model_copy(update={"position_in_item": elem_pos})
                )
            elem_pos += 1
            global_pos += 1
            if sd.direction_type == "adoption":
                # In the newer PDF format the country lists appear *before* the
                # adoption line.  If we buffered them, prepend to the following
                # blocks so extract_resolution_from_adoption can see both the
                # recorded-vote signal and the country lists.
                if _after_vote_signal:
                    _try_add_resolution(
                        section,
                        _pending_vote_blocks + _following(section),
                        _last_resolution_header_text,
                    )
                else:
                    _try_add_resolution(
                        section, _following(section), _last_resolution_header_text
                    )
                _after_vote_signal = False
                _pending_vote_blocks = []
            elif re.search(
                r"(?:recorded\s+)?vote\s+was\s+taken", sd.text, re.IGNORECASE
            ):
                # Begin buffering: include the signal block itself so that
                # extract_resolution_from_adoption can detect has_recorded_signal.
                _after_vote_signal = True
                _pending_vote_blocks = list(section.blocks)
            elif _after_vote_signal and re.match(
                r"^(?:In\s+favour|Against|Abstaining)\s*:",
                sd.text.strip(),
                re.IGNORECASE,
            ):
                # Vote-category headers ("In favour:", "Against:", "Abstaining:")
                # are italic stage directions; include them in the pending buffer
                # so _extract_country_votes can attribute each country list to
                # the correct vote position.
                _pending_vote_blocks.extend(section.blocks)

        # ---- Resolution header ---------------------------------------------------
        elif section.section_type == "resolution_header":
            # Track so that a following "The draft resolution was adopted." line
            # can recover the symbol from this header.
            _last_resolution_header_text = section.text
            # Sub-heading within an item; also check for embedded adoption.
            _try_add_resolution(
                section, _following(section), _last_resolution_header_text
            )

        # ---- Body ----------------------------------------------------------------
        elif section.section_type == "body":
            if _after_vote_signal:
                # Country-list blocks (In favour: …, Against: …, Abstaining: …)
                # accumulate here; they are passed as context when the adoption
                # line is encountered.
                _pending_vote_blocks.extend(section.blocks)
            # All-bold section (1 or 2 blocks) looks like a named heading.
            # Single-block: GA/SC topic lines; two-block: SC topic + reference
            # document line (e.g. "The situation in… / Letter dated 19 March…").
            # Exclude ALL-CAPS blocks — those are GA resolution/document titles,
            # not section boundaries.
            elif (
                len(section.blocks) <= 2
                and all(b.bold_start for b in section.blocks)
                and len(section.text.strip()) < 300
                and not all(b.text.strip().isupper() for b in section.blocks)
            ):
                _flush_and_start(title=section.text.strip(), item_type="other_item")
            elif current is not None and current.speeches:
                # Continuation text after a stage direction mid-speech:
                # append to the most recent speech so the full speech is
                # preserved and document order can be reconstructed.
                last_speech = current.speeches[-1]
                appended_text = last_speech.text.rstrip() + " " + section.text.strip()
                current.speeches[-1] = last_speech.model_copy(
                    update={"text": appended_text}
                )

    if current is not None:
        items.append(current)

    return items


# ---------------------------------------------------------------------------
# Pipeline entry point
# ---------------------------------------------------------------------------


class ExtractionError(Exception):
    """Raised when a PDF cannot be processed."""

    def __init__(self, pdf_path: Path, phase: str, cause: Exception) -> None:
        super().__init__(f"[{phase}] {pdf_path}: {cause}")
        self.pdf_path = pdf_path
        self.phase = phase
        self.cause = cause


def process_pdf(
    pdf_path: Path,
    output_dir: Path | None = None,
    use_llm: bool = False,
    llm_api_key: str | None = None,
    debug_dir: Path | None = None,
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
    debug_dir:
        If given, intermediate artifacts are written to
        ``debug_dir/<pdf_stem>/`` for post-mortem inspection.

    Returns
    -------
    MeetingRecord
        The fully extracted and validated meeting record.

    Raises
    ------
    ExtractionError
        If any pipeline phase fails.
    """
    import json as _json

    log.info("Processing %s", pdf_path)

    def _debug_write(name: str, content: str) -> None:
        if debug_dir is None:
            return
        # Mirror the data/raw_pdfs/… tree under debug_dir so debug artifacts
        # sit at the same relative position as their source PDF.
        parts = pdf_path.parts
        if "raw_pdfs" in parts:
            idx = parts.index("raw_pdfs")
            rel = Path(*parts[idx + 1 :]).with_suffix(
                ""
            )  # e.g. en/ga/65/pv/document_71
        else:
            rel = Path(pdf_path.stem)
        d = debug_dir / rel
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(content, encoding="utf-8")

    # --- Phase 1: PDF ingestion ------------------------------------------------
    try:
        raw_pages = extract_pages(pdf_path)
        clean = clean_pages(raw_pages)
        blocks = flatten_blocks(clean)
    except Exception as exc:
        raise ExtractionError(pdf_path, "pdf_ingestion", exc) from exc

    _debug_write(
        "01_blocks.txt",
        "\n".join(
            f"[p{b.page_num} x={b.x0:.0f} y={b.y0:.0f}] {b.text!r}" for b in blocks
        ),
    )

    # --- Phase 2: Structure detection ------------------------------------------
    try:
        sections = detect_sections(blocks)
    except Exception as exc:
        raise ExtractionError(pdf_path, "structure_detection", exc) from exc

    _debug_write(
        "02_sections.txt",
        "\n\n".join(
            f"=== {s.section_type} ({len(s.blocks)} blocks) ===\n{s.text}"
            for s in sections
        ),
    )

    # --- Phase 3: Metadata extraction ------------------------------------------
    try:
        cover_blocks = [
            b for s in sections if s.section_type == "cover" for b in s.blocks
        ]
        meta: dict[str, Any] = extract_metadata(cover_blocks)

        # Symbol lives in the running page header, which clean_text strips.
        # Fall back to the raw (uncleaned) first-page blocks.
        # Raw first-page text (all blocks, both columns, uncleaned) is used as a
        # fallback source for metadata that lives in the running page header.
        raw_first_page_text = " ".join(b.text for b in raw_pages[0])

        if not meta.get("symbol"):
            from src.extraction.metadata_extractor import extract_symbol

            fallback_symbol = extract_symbol(raw_first_page_text)
            if fallback_symbol:
                from src.extraction.metadata_extractor import (
                    extract_body,
                    extract_session,
                )

                meta["symbol"] = fallback_symbol
                body = extract_body(fallback_symbol)
                meta["body"] = body
                if not meta["session"]:
                    if body == "SC":
                        from src.extraction.metadata_extractor import extract_sc_session

                        meta["session"] = extract_sc_session(raw_first_page_text)
                    else:
                        meta["session"] = extract_session(fallback_symbol)
                log.debug("Symbol recovered from raw page header: %s", fallback_symbol)

        # Second fallback: reconstruct symbol from the folder path + meeting ordinal
        # in the page text.  Older GA PV documents (sessions ~31–48) were scanned
        # from printed volumes and do not include the "A/NN/PV.NN" running header.
        # The session number is reliably encoded in the directory structure:
        #   …/ga/{session}/pv/document_N.pdf
        # The meeting number is extracted from "Nth PLENARY" cover text.
        if not meta.get("symbol"):
            from src.extraction.metadata_extractor import extract_meeting_number

            session_from_path = _session_from_path(pdf_path)
            meeting_from_text = extract_meeting_number(raw_first_page_text)
            if session_from_path and meeting_from_text:
                body_prefix = (
                    "S" if "SECURITY COUNCIL" in raw_first_page_text.upper() else "A"
                )
                reconstructed = (
                    f"{body_prefix}/{session_from_path}/PV.{meeting_from_text}"
                )
                meta["symbol"] = reconstructed
                meta["session"] = meta["session"] or session_from_path
                meta["meeting_number"] = meeting_from_text
                meta["body"] = "SC" if body_prefix == "S" else "GA"
                log.debug("Symbol reconstructed from path+text: %s", reconstructed)

        # Date and location may be in the right-column header (older PDFs) rather
        # than in the cover section blocks.  Fall back to the raw first-page text.
        if not meta.get("date"):
            from src.extraction.metadata_extractor import extract_date

            meta["date"] = extract_date(raw_first_page_text)
            if meta["date"]:
                log.debug("Date recovered from raw page: %s", meta["date"])

        if not meta.get("location"):
            from src.extraction.metadata_extractor import extract_location

            # Restrict to the first 20 blocks of page 0: the location line always
            # appears in the cover header, well before any speech content.
            # (In older two-column OCR scans the header is spread across ~17 blocks
            # due to column interleaving, so 10 would be too few.)
            first_page_header = " ".join(b.text for b in raw_pages[0][:20])
            meta["location"] = extract_location(first_page_header)
            if meta["location"]:
                log.debug("Location recovered from raw page: %s", meta["location"])

        # Meeting number must come from the symbol (PV.N) — the cover text may
        # not contain "Nth plenary meeting" for older PDFs where that line was
        # only in the stripped running header.  Always prefer symbol-derived value
        # because the text-based pattern can match incidental ordinals in speech.
        if meta.get("symbol"):
            from src.extraction.metadata_extractor import extract_meeting_number

            sym_meeting_num = extract_meeting_number("", meta["symbol"])
            if sym_meeting_num:
                meta["meeting_number"] = sym_meeting_num
    except Exception as exc:
        raise ExtractionError(pdf_path, "metadata_extraction", exc) from exc

    _debug_write(
        "03_metadata.json",
        _json.dumps(
            {
                k: str(v) if not isinstance(v, (str, int, float, type(None))) else v
                for k, v in meta.items()
            },
            indent=2,
        ),
    )
    _debug_write("03_cover_text.txt", " ".join(b.text for b in cover_blocks))

    # --- Phase 3b: Item grouping -----------------------------------------------
    try:
        items = _group_into_items(sections)
    except Exception as exc:
        raise ExtractionError(pdf_path, "item_grouping", exc) from exc

    _debug_write(
        "03_items.txt",
        "\n\n".join(
            f"[item {item.position}] {item.item_type}: {item.title!r}\n"
            f"  speeches={len(item.speeches)}, "
            f"stage_dirs={len(item.stage_directions)}, "
            f"resolutions={len(item.resolutions)}"
            for item in items
        ),
    )

    # Build adoption context map for LLM resolution title extraction.
    _adoption_context: dict[str, str] = {}
    for _i, _sec in enumerate(sections):
        if "was adopted" in _sec.text.lower():
            _ctx_start = max(0, _i - 8)
            _ctx = "\n".join(s.text for s in sections[_ctx_start : _i + 1])
            for _item in items:
                for _res in _item.resolutions:
                    if (
                        _res.draft_symbol in _sec.text
                        and _res.draft_symbol not in _adoption_context
                    ):
                        _adoption_context[_res.draft_symbol] = _ctx

    # Extract resolution titles from the adoption context using the "entitled"
    # pattern (e.g. "draft resolution A/76/L.86, entitled 'Financing for …'").
    for _item in items:
        for _res in _item.resolutions:
            if not _res.title and _res.draft_symbol in _adoption_context:
                _res.title = extract_resolution_title(
                    _adoption_context[_res.draft_symbol], _res.draft_symbol
                )

    # --- Phase 4: LLM semantic enrichment (optional) ---------------------------
    if use_llm:
        try:
            from src.llm.semantic_extractor import SemanticExtractor

            llm = SemanticExtractor(api_key=llm_api_key)

            for item in items:
                for i, speech in enumerate(item.speeches):
                    if not speech.speaker.on_behalf_of and speech.text:
                        group = llm.extract_group_affiliation(speech.text[:500])
                        if group:
                            item.speeches[i] = speech.model_copy(
                                update={
                                    "speaker": speech.speaker.model_copy(
                                        update={"on_behalf_of": group}
                                    )
                                }
                            )

                for res in item.resolutions:
                    if res.country_votes:
                        raw_names = list({cv.country for cv in res.country_votes})
                        norm_map = llm.normalise_countries(raw_names)
                        res.country_votes = [
                            cv.model_copy(
                                update={
                                    "country": norm_map.get(cv.country) or cv.country
                                }
                            )
                            for cv in res.country_votes
                        ]

                for res in item.resolutions:
                    if not res.title and res.draft_symbol in _adoption_context:
                        title = llm.extract_resolution_title(
                            res.draft_symbol, _adoption_context[res.draft_symbol]
                        )
                        if title:
                            res.title = title

        except Exception as exc:
            log.warning("LLM enrichment failed for %s: %s", pdf_path, exc)

    # --- Phase 5: Assemble and validate ----------------------------------------
    try:
        symbol: str = meta.get("symbol") or ""
        _session_raw = meta.get("session")
        session_num: int | None = (
            int(_session_raw) if _session_raw is not None else None
        )
        meeting_num: int = int(meta.get("meeting_number") or 0)
        doc_date: date | None = meta.get("date")
        if doc_date is None:
            log.warning("Date not found in %s", pdf_path.name)
        location: str = meta.get("location") or ""
        president: PresidentInfo | None = meta.get("president")
        doc_body: str = meta.get("body") or "GA"

        record = MeetingRecord(
            symbol=symbol,
            body=doc_body,
            session=session_num,
            meeting_number=meeting_num,
            date=doc_date,
            location=location,
            president=president,
            items=items,
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
