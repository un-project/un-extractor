# AGENTS.md

This file describes the repository, its goals, and how agents should work within it.

## Project overview

This repository builds a pipeline to extract structured data from United Nations meeting
verbatim records (procès-verbaux) distributed as PDFs and store the results in PostgreSQL.

Target dataset: ~8000 PDFs of GA and SC plenary meetings.
Each PDF is a verbatim record of one meeting (~30 pages, two-column layout).

PDFs are downloaded via [un-scraper](https://github.com/un-project/un-scraper), which
produces the directory structure `data/raw_pdfs/{lang}/{body}/{session}/pv/document_{N}.pdf`.

See [PLAN.md](PLAN.md) for the full architecture, phase breakdown, and database schema.

## Repository layout

    data/
        raw_pdfs/
            {lang}/{body}/{session}/pv/document_{N}.pdf
            # Example: en/ga/64/pv/document_121.pdf → A/64/PV.121
        undl/           # cached UNDL voting CSVs (downloaded on first import)
        crUnsc/         # cached CR-UNSC zips (downloaded on first import)

    src/
        pdf/            # Phase 1: text extraction and cleaning
        structure/      # Phase 2: document segmentation
        extraction/     # Phase 3: rule-based extractors
            country_aliases.py   # static alias table + normalize_country_name()
        llm/            # Phase 4: LLM semantic extraction
        validation/     # Phase 5: JSON schema validation
        db/             # Phase 6: PostgreSQL models and import
        pipeline/       # orchestration (single PDF and batch)
        models.py       # shared Pydantic output models (MeetingRecord, Speech, …)

    scripts/
        import_undl_votes.py          # download & upsert UNDL voting CSVs
        fix_country_duplicates.py     # merge/clean duplicate country rows in DB
        import_crUnsc_pdfs.py         # place CR-UNSC SC meeting PDFs into raw_pdfs/
        import_crUnsc_texts.py        # upsert resolution full texts from CR-UNSC
        import_crUnsc_citations.py    # import citation network into resolution_citations
        import_undl_general_debate.py    # import General Debate speeches metadata
        import_undl_member_states.py     # enrich countries with m49, membership dates
        import_undl_ga_resolutions.py    # upsert GA resolution metadata (all 20k)
        import_undl_representatives.py   # permanent reps + SC reps tables

    tests/
        fixtures/       # 10 golden JSON summaries for integration tests
    configs/
    output/             # generated JSON files (not committed)

## Development commands

    # Install dependencies (uses uv)
    uv sync

    # Process a single PDF (outputs JSON to output/)
    python src/pipeline/process_pdf.py data/raw_pdfs/en/ga/64/pv/document_121.pdf

    # Process a single PDF with debug artifacts
    python src/pipeline/process_pdf.py \
        data/raw_pdfs/en/ga/64/pv/document_121.pdf \
        --output output/ --debug output/debug/

    # Process full dataset in parallel
    python process_dataset.py data/raw_pdfs/ --output output/ --workers 8

    # Import JSON to database (set DATABASE_URL first)
    python import_json_to_db.py output/

    # Import authoritative UNDL voting CSVs
    python scripts/import_undl_votes.py --db postgresql://user:pass@host/db

    # Merge/clean duplicate country rows (run after each import)
    python scripts/fix_country_duplicates.py --db postgresql://user:pass@host/db

    # CR-UNSC integration (run in order after import_undl_votes.py)
    python scripts/import_crUnsc_pdfs.py            # place SC PDFs into data/raw_pdfs/
    python scripts/import_crUnsc_texts.py  --db ... # upsert full_text + crUnsc_id
    python scripts/import_crUnsc_citations.py --db ... # populate resolution_citations

    # General Debate speeches metadata (DHL dataset, sessions 1–79)
    python scripts/import_undl_general_debate.py --db ...

    # DHL supplementary datasets
    python scripts/import_undl_member_states.py --db ...       # m49, membership dates
    python scripts/import_undl_ga_resolutions.py --db ...      # GA resolution metadata
    python scripts/import_undl_representatives.py --db ...     # ambassadors + SC reps

    # Run tests
    pytest tests/

## PDF format — what to know before writing code

**Two-column layout.** The body of every page uses two columns. PyMuPDF's default
`page.get_text()` and even `sort=True` produce wrong reading order for two-column layouts
(they sort top-to-bottom across the whole page width). Instead:

- Use `page.get_text("dict")` for span-level data with bounding boxes and font flags.
- Use `column_boxes()` from `pymupdf-utilities` to detect column bounding boxes in
  correct reading order. Then extract each column via `page.get_text("dict", clip=rect)`.

**Bold/italic detection.** Font flags in `span['flags']` are the primary source:
- `flags & 0x10` → bold (speaker names)
- `flags & 0x02` → italic (stage directions, adoption lines)
Supplement with `"Bold"` / `"Italic"` in `span['font']` for malformed PDFs.

**Document symbol.** Each page header contains the symbol `A/{session}/PV.{N}` (or `S/...`
for Security Council). This is the primary identifier. The meeting number is extracted
**directly from the symbol** (`PV.N` → N) as the primary source, with "Nth plenary meeting"
text in the cover as a fallback.

**Speaker turns.** Speaker names are bold in the original PDF. The pattern is:

    Mr./Mrs./Ms. LastName (Country): text
    Mr./Mrs./Ms. LastName (Country) (spoke in Language): text
    The President (spoke in Arabic): text

Extract the bold flag from PyMuPDF span metadata (`flags & 0x10`), not just text patterns.
All speakers are stored in the `speakers` table including those without a country (The
President, The Secretary-General, Secretariat staff) — these have `country_id = null`.

**Important:** Raw PDF text blocks often have leading/trailing whitespace. Always call
`.strip()` before applying regex patterns anchored with `^`. The attribution regex
(`_TITULAR_ATTR_RE`, `_SPEAKER_ATTR_RE`) and the text split must both operate on the
same stripped string to avoid off-by-one position errors.

**Stage directions.** Italic text records procedural events (e.g. *It was so decided.*,
*The meeting rose at 5.20 p.m.*). They are not speeches, but **they must be stored in the
`stage_directions` table** because the full procedural record must be preserved.

Document order is reconstructed using a **shared `position_in_item` counter** within each
`DocumentItem`. Speeches, stage directions, and resolutions within the same item all share
this counter and can be sorted by it to replay the meeting flow in exact order. To
reconstruct the full document:

1. Sort `DocumentItem` objects by `item.position`.
2. Within each item, merge speeches, stage directions, and resolutions sorted by
   `position_in_item`.

Stage directions on the cover page (e.g. *The meeting was called to order at 3.30 p.m.*)
are captured as the first stage direction of the first `DocumentItem`, not buried in cover
metadata.

When a stage direction appears mid-speech (between paragraphs), the speech text before
and after the stage direction is preserved: the continuation text is appended to the
preceding speech so no content is lost. The stage direction itself keeps its own
`position_in_item` between the two speech segments.

**Consensus vs. recorded votes.** When "It was so decided." follows an adoption line,
the vote was by consensus — assume all members agreed; no `country_votes` rows are created.
When a recorded vote occurs, the verbatim record prints the signal line "A recorded vote was
taken." followed by per-country breakdown and then vote totals:

    A recorded vote was taken.
    In favour: Algeria, Angola, Argentina, ...
    Against: Israel, United States of America
    Abstaining: Australia, Canada, ...
    Draft resolution I was adopted by 109 votes to 41, with 35 abstentions (resolution 65/206).

Extract these lists to populate the `country_votes` table. Each country name must be
matched to the `countries` table (use LLM normalisation if no exact match).

**Adoption line patterns.** Several formats exist:

    Draft resolution A/64/L.72 was adopted (resolution 64/299).   ← named symbol
    Draft resolution I was adopted (resolution 65/206).            ← Roman numeral
    The amendment (A/65/L.53) was adopted by N votes to M.        ← amendment
    The draft decision was adopted.                                ← generic

The draft symbol `A/{session}/L.{N}` and the adopted symbol `{session}/{N}` are both
extractable by regex.

## LLM usage

Use the Claude API with model `claude-sonnet-4-6`. The API key is expected in environment
variable `ANTHROPIC_API_KEY`.

Always use:

    temperature = 0
    response_format = JSON (or instruct model to return JSON only)

Use LLM only for:
- extracting resolution titles from context
- inferring delegate group affiliations
- handling edge cases that rule-based extraction cannot cover

**Country name normalisation** is handled entirely by the static alias table in
`src/extraction/country_aliases.py` via `normalize_country_name()`. This covers OCR
typos, DHL CSV formats, historical names, and mixed-case artifacts. LLM is not used
for country names.

Do not use LLM for things extractable by regex (dates, symbols, speaker names, vote counts).

## Database

PostgreSQL. Connection string expected in environment variable `DATABASE_URL`.

Schema is defined in `src/db/models.py`. See PLAN.md § Phase 6 for the full table
definitions and rationale (in particular: never store raw country name strings in vote
tables — always use `country_id` FK to the `countries` table).

## Testing approach

- Unit tests for each extractor (regex patterns, edge cases)
- Integration tests using the sample PDFs in `data/raw_pdfs/`
- Fixture files in `tests/fixtures/` — 10 golden JSON summaries, one per sample PDF
- Sample PDFs span GA sessions 31–79 and SC meetings:
  - `en/ga/31/pv/document_8.pdf` — A/31/PV.8: scanned 1976 document, OCR text layer, ALL-CAPS names
  - `en/ga/48/pv/document_46.pdf` — A/48/PV.46: 1993 format, ALL-CAPS names
  - `en/ga/61/pv/document_107.pdf` — A/61/PV.107: recorded votes, country vote lists
  - `en/ga/64/pv/document_121.pdf` — A/64/PV.121: consensus adoptions
  - `en/ga/65/pv/document_71.pdf` — A/65/PV.71: amendments, Roman-numeral draft labels
  - `en/ga/76/pv/document_102.pdf` — A/76/PV.102: recent GA format
  - `en/ga/79/pv/document_29.pdf` — A/79/PV.29: recent GA format with recorded vote
  - `en/sc/1997/pv/document_3756.pdf` — S/PV.3756: Security Council 1997
  - `en/sc/2018/pv/document_8422.pdf` — S/PV.8422: Security Council 2018
  - `en/sc/2026/pv/document_10100.pdf` — S/PV.10100: Security Council 2026

Regenerate fixtures after intentional pipeline changes using the snippet in `tests/test_integration.py`'s docstring.

## Error handling conventions

Every pipeline stage should catch its own errors and propagate structured failure objects:

    {
      "pdf_path": "...",
      "phase": "speaker_extraction",
      "error": "...",
      "timestamp": "..."
    }

Failed documents go to `output/failed/`. Never silently drop data.

## Style conventions

- Python 3.11+
- Type hints on all public functions
- Dataclasses or Pydantic models for structured data (prefer Pydantic for validation)
- No global state; pass config explicitly
- Keep extractors stateless and testable in isolation
