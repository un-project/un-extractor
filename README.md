# un-extractor

A pipeline that converts United Nations meeting verbatim records (procès-verbaux) from PDF into structured JSON and stores them in PostgreSQL.

**Target dataset:** ~8,000 PDFs of GA and SC plenary meetings, each ~30 pages in a two-column layout.

---

## Overview

Each UN meeting PDF contains:
- Cover page with document symbol, date, president, and location
- Agenda items with speeches by member-state delegates
- Stage directions (italic procedural text: adoptions, suspensions, adjournments)
- Draft resolutions and recorded or consensus votes

The pipeline extracts all of this into a structured JSON document and optionally stores it in PostgreSQL.

---

## Project structure

```
data/
    raw_pdfs/
        {lang}/{body}/{session}/pv/document_{N}.pdf
        # e.g. en/ga/64/pv/document_121.pdf → A/64/PV.121

src/
    pdf/            # Phase 1 – column-aware text extraction and cleaning
    structure/      # Phase 2 – document segmentation into typed sections
    extraction/     # Phase 3 – rule-based extractors (metadata, speakers, votes)
    llm/            # Phase 4 – Claude API semantic extraction
    validation/     # Phase 5 – JSON schema validation
    db/             # Phase 6 – SQLAlchemy ORM models and database importer
    pipeline/       # Orchestration (single PDF and batch)

output/             # Generated JSON files (not committed)
    meeting_{symbol}.json
    failed/         # Failed PDFs with error metadata
    debug/          # Intermediate debug artifacts (see --debug flag)
        {lang}/{body}/{session}/pv/{document}/
            01_blocks.txt
            02_sections.txt
            03_metadata.json
            03_cover_text.txt
            03_items.txt

tests/
configs/
```

---

## Installation

```bash
# Create a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

Requires Python 3.11+.

---

## Usage

### Process a single PDF

```bash
python src/pipeline/process_pdf.py data/raw_pdfs/en/ga/64/pv/document_121.pdf
```

With debug output:

```bash
python src/pipeline/process_pdf.py \
    data/raw_pdfs/en/ga/64/pv/document_121.pdf \
    --output output/ \
    --debug output/debug/
```

With LLM enrichment (requires `ANTHROPIC_API_KEY`):

```bash
python src/pipeline/process_pdf.py \
    data/raw_pdfs/en/ga/64/pv/document_121.pdf \
    --output output/ \
    --llm
```

### Process the full dataset

```bash
python process_dataset.py data/raw_pdfs/ --output output/ --workers 8
```

### Import JSON to database

#### 1. Create a PostgreSQL database

```bash
createdb undb
```

Or inside `psql`:

```sql
CREATE DATABASE undb;
```

#### 2. Set the connection string

```bash
export DATABASE_URL="postgresql://user:pass@localhost/undb"
```

#### 3. Create the schema

The schema is created automatically on first import. You can also create it manually:

```bash
python - <<'EOF'
from src.db.database import create_schema, get_engine
create_schema(get_engine())
print("Schema created.")
EOF
```

This runs `CREATE TABLE IF NOT EXISTS` for all tables — safe to call repeatedly.

#### 4. Run the importer

```bash
python import_json_to_db.py output/
# or with an explicit URL:
python import_json_to_db.py output/ --db postgresql://user:pass@localhost/undb
```

The importer is idempotent per document: re-importing a JSON file for a symbol already in the database is a no-op.

#### Database schema overview

| Table | Description |
|---|---|
| `countries` | UN member states (name, ISO-2, ISO-3) |
| `speakers` | People who spoke; linked to a country |
| `documents` | One row per meeting PDF (symbol, date, session, location) |
| `document_items` | Agenda items and named sections within a meeting |
| `stage_directions` | Italic procedural text (adoptions, suspensions, …) |
| `speeches` | One speech segment per speaker turn |
| `resolutions` | Draft/adopted resolutions; shared across meetings |
| `votes` | One voting event per resolution per meeting |
| `country_votes` | Per-country vote position for recorded votes |
| `amendments` | (reserved) proposed amendments |

Key relationships:
- `speeches` → `speakers` → `countries`
- `votes` → `resolutions`; `country_votes` → `votes` + `countries`
- All content rows link back to `documents` and `document_items`

To reconstruct the full text of a meeting in order, join `document_items` (ordered by `position`), then merge `speeches`, `stage_directions`, and `votes` within each item on `position_in_item`.

### Run tests

```bash
pytest tests/
```

---

## Output format

Each processed PDF produces one JSON file (`output/meeting_{symbol}.json`) conforming to this schema:

```json
{
  "symbol": "A/64/PV.121",
  "body": "GA",
  "session": 64,
  "meeting_number": 121,
  "date": "2010-09-13",
  "location": "New York",
  "president": { "name": "Mr. Ali Abdussalam Treki", "country": "Libyan Arab Jamahiriya" },
  "items": [
    {
      "position": 0,
      "item_type": "agenda_item",
      "title": "Prevention of armed conflict",
      "agenda_number": 13,
      "sub_item": null,
      "continued": false,
      "speeches": [
        {
          "position": 0,
          "position_in_item": 0,
          "speaker": { "name": "Mr. Alsaidi", "country": "Yemen", "language": null, "role": null, "title": "Mr.", "on_behalf_of": null },
          "text": "..."
        }
      ],
      "stage_directions": [
        {
          "position": 1,
          "position_in_item": 1,
          "text": "Draft resolution A/64/L.72 was adopted (resolution 64/299).",
          "direction_type": "adoption"
        }
      ],
      "resolutions": [
        {
          "draft_symbol": "A/64/L.72",
          "adopted_symbol": "64/299",
          "title": null,
          "vote_type": "consensus",
          "yes_count": null,
          "no_count": null,
          "abstain_count": null,
          "country_votes": [],
          "position_in_item": 2
        }
      ]
    }
  ]
}
```

### Reconstructing document order

Within each `DocumentItem`, speeches, stage directions, and resolutions share a common `position_in_item` counter. To replay the meeting flow in order:

```python
all_elements = (
    [("speech", s.position_in_item, s) for s in item.speeches]
    + [("stage_direction", d.position_in_item, d) for d in item.stage_directions]
    + [("resolution", r.position_in_item, r) for r in item.resolutions]
)
all_elements.sort(key=lambda x: x[1])
```

For the full document, order items by `item.position` first, then apply the above within each item.

---

## Environment variables

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Claude API key (required for `--llm` mode) |
| `DATABASE_URL` | PostgreSQL connection string (required for DB import) |

---

## PDF format notes

**Two-column layout.** All body pages use two columns. The extractor uses PyMuPDF's `get_text("dict")` with column-aware bounding-box clipping to read left column then right column.

**Bold = speaker.** Speaker attributions appear in bold: `Mr. Smith (Country):`.

**Italic = stage direction.** Procedural text (adoptions, suspensions, etc.) is always italic.

**Scanned / older documents.** PDFs from the 1970s–1980s are scanned images with an OCR text layer. They lack bold/italic metadata, so speaker detection falls back to the ALL-CAPS surname pattern used in that era: `1. Mr. SURNAME (Country):`. The paragraph number prefix and occasional `;` separator (OCR error for `:`) are handled automatically. Language notes may appear as `(interpretation from Spanish)` rather than `(spoke in Spanish)`.

**Document symbol.** Appears in the page header: `A/{session}/PV.{meeting_number}`. Meeting number is extracted from this symbol (e.g. `A/61/PV.107` → meeting 107).

**Votes.** Consensus votes are signalled by "It was so decided." Recorded votes include the line "A recorded vote was taken." followed by country lists (`In favour:`, `Against:`, `Abstaining:`) and a summary line with totals.

**Amendments.** Amendment votes follow the pattern "The amendment (A/65/L.53) was adopted by N votes to M, with K abstentions."

---

## Sample PDFs

Four sample PDFs are included in `data/raw_pdfs/`:

| File | Symbol | Notes |
|---|---|---|
| `en/ga/31/pv/document_8.pdf` | A/31/PV.8 | Scanned (1976): OCR text layer, ALL-CAPS names, inline speaker format |
| `en/ga/48/pv/document_46.pdf` | A/48/PV.46 | Older format (1993): ALL-CAPS names, no dot-leaders |
| `en/ga/61/pv/document_107.pdf` | A/61/PV.107 | Recorded votes, country vote lists |
| `en/ga/64/pv/document_121.pdf` | A/64/PV.121 | Consensus adoptions |
| `en/ga/65/pv/document_71.pdf` | A/65/PV.71 | Amendments, many resolutions |
| `en/ga/76/pv/document_102.pdf` | A/76/PV.102 | Recent format |

---

## Architecture

See [PLAN.md](PLAN.md) for the full six-phase pipeline description, database schema, and design rationale.

See [AGENTS.md](AGENTS.md) for agent guidance and project conventions.
