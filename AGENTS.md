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

    src/
        pdf/            # Phase 1: text extraction and cleaning
        structure/      # Phase 2: document segmentation
        extraction/     # Phase 3: rule-based extractors
        llm/            # Phase 4: LLM semantic extraction
        validation/     # Phase 5: JSON schema validation
        db/             # Phase 6: PostgreSQL models and import
        pipeline/       # orchestration (single PDF and batch)

    tests/
    configs/
    output/             # generated JSON files (not committed)

## Development commands

There is no build system yet. When one is set up, document the key commands here:

    # Install dependencies
    pip install -r requirements.txt

    # Process a single PDF
    python src/pipeline/process_pdf.py data/raw_pdfs/en/ga/64/pv/document_121.pdf

    # Process full dataset
    python process_dataset.py data/raw_pdfs/

    # Import JSON to database
    python import_json_to_db.py output/

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
for Security Council). This is the primary identifier.

**Speaker turns.** Speaker names are bold in the original PDF. The pattern is:

    Mr./Mrs./Ms. LastName (Country): text
    Mr./Mrs./Ms. LastName (Country) (spoke in Language): text
    The President (spoke in Arabic): text

Extract the bold flag from PyMuPDF span metadata (`flags & 0x10`), not just text patterns.
All speakers are stored in the `speakers` table including those without a country (The
President, The Secretary-General, Secretariat staff) — these have `country_id = null`.

**Stage directions.** Italic text records procedural events (e.g. *It was so decided.*,
*The meeting rose at 5.20 p.m.*). They are not speeches, but **they must be stored in the
`stage_directions` table** because the full procedural record must be preserved. Each row
has `position_in_document` so the complete meeting sequence can be reconstructed by
ordering both `speeches` and `stage_directions` by that field.

**Consensus vs. recorded votes.** When "It was so decided." follows an adoption line,
the vote was by consensus — assume all members agreed; no `country_votes` rows are created.
When a recorded vote occurs, the verbatim record prints vote totals AND a full per-country
breakdown in the format:

    In favour: Algeria, Angola, Argentina, ...
    Against: Israel, United States of America
    Abstaining: Australia, Canada, ...

Extract these lists to populate the `country_votes` table. Each country name must be
matched to the `countries` table (use LLM normalisation if no exact match).

**Adoption line pattern.**

    Draft resolution A/64/L.72 was adopted (resolution 64/299).

The draft symbol `A/{session}/L.{N}` and the adopted symbol `{session}/{N}` are both
extractable by regex.

## LLM usage

Use the Claude API with model `claude-sonnet-4-6`. The API key is expected in environment
variable `ANTHROPIC_API_KEY`.

Always use:

    temperature = 0
    response_format = JSON (or instruct model to return JSON only)

Use LLM only for:
- normalising country names to UN official form
- extracting resolution titles from context
- inferring delegate group affiliations
- handling edge cases that rule-based extraction cannot cover

Do not use LLM for things extractable by regex (dates, symbols, speaker names, vote counts).

## Database

PostgreSQL. Connection string expected in environment variable `DATABASE_URL`.

Schema is defined in `src/db/models.py`. See PLAN.md § Phase 6 for the full table
definitions and rationale (in particular: never store raw country name strings in vote
tables — always use `country_id` FK to the `countries` table).

## Testing approach

- Unit tests for each extractor (regex patterns, edge cases)
- Integration tests using the sample PDFs in `data/raw_pdfs/`
- Fixture files in `tests/fixtures/` for verified extraction outputs
- The three sample PDFs cover sessions 61, 64, and 76 and give good coverage of format
  variation across years

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
