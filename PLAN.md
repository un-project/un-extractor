# Agent mission

Goal:

    Build a scalable pipeline that converts UN meeting PDFs into structured JSON and stores them in a database.

Target dataset:

- ~8000 PDFs
- ~30 pages each
- Sources: meetings of the United Nations, especially
    - United Nations General Assembly (GA)
    - United Nations Security Council (SC)

# Observed PDF structure

These observations are based on reading the sample PDFs in `data/raw_pdfs/`.

## File path structure

    data/raw_pdfs/{lang}/{body}/{session}/pv/document_{N}.pdf

- `lang`: language code (e.g. `en`)
- `body`: `ga` for General Assembly, `sc` for Security Council
- `session`: session number (e.g. `64`, `76`, `61`)
- `pv`: procès-verbal (verbatim record type)
- `document_{N}.pdf`: N is the meeting number within the session

## Document symbol

The document symbol appears in the top-right corner of each page:

    A/{session}/PV.{meeting_number}

Examples: `A/64/PV.121`, `A/76/PV.102`, `A/61/PV.107`

- `A` = General Assembly (Security Council would use `S`)
- `{session}` = session number
- `PV` = Procès-Verbal (verbatim record)
- `{meeting_number}` = ordinal meeting number within the session

## Cover page structure (page 1)

    United Nations                              A/64/PV.121
    [logo] General Assembly                     Official Records
           Sixty-fourth session

           121st plenary meeting
           Monday, 13 September 2010, 3 p.m.
           New York

    President: Mr. Ali Abdussalam Treki ........ (Libyan Arab Jamahiriya)

    The meeting was called to order at 3.30 p.m.   [italic]

    [footer: document code e.g. "10-53066 (E)", disclaimer text]

## Page layout

- **Two-column layout** on all body pages — critical for text extraction.
  PyMuPDF must extract columns left-to-right within each column, not across the full
  page width, otherwise text will be scrambled.
- Running header on body pages: document symbol (left) and date (right, in newer docs)
- Page numbers at bottom: either plain (`2`, `3`) or fractional (`2/31`, `3/31`)

## Agenda items

Agenda items appear as bold headers:

    Agenda item 13
    Prevention of armed conflict

    Agenda item 53 (continued)
    Sustainable development

        (b) Follow-up to the Mauritius Strategy...

Sub-items use letter labels: (a), (b), (f), etc.
`(continued)` means this item carries over from a previous meeting.

## Draft resolutions and decisions

Draft symbols follow the pattern `A/{session}/L.{N}`:

    Draft resolution (A/64/L.72)
    Draft decision (A/76/L.79)

Adoption is recorded in an italic line:

    Draft resolution A/64/L.72 was adopted (resolution 64/299).
    Draft decision A/76/L.79 was adopted (decision 76/575).
    Draft decision A/64/L.71, as orally corrected, was adopted.

After adoption the symbol changes: `A/64/L.72` → resolution `64/299`.

## Speaker patterns

Speaker attribution appears as a bold name followed by country in parentheses:

    Mr. Alsaidi (Yemen): speech text...
    Mrs. Salazar-Mejía (Colombia) (spoke in Spanish): speech text...
    Mr. Dai Bing (China) (spoke in Chinese): speech text...
    The President (spoke in Arabic): presidential text...
    The President: presidential text...
    Ms. Sharma (Department for General Assembly and Conference Management): ...

Key rules:
- Name is **bold** in the original PDF
- Country is in parentheses immediately after the name
- Optional language note `(spoke in Language)` follows the country
- Titular roles (`The President`, `The Secretary-General`) have no country — store with
  null `country_id` but still create a speakers row
- Secretariat speakers use department/office as their affiliation, not a country — also
  stored with null `country_id`
- All speakers, including those without affiliation, must be stored in the `speakers` table
- Delegates sometimes speak on behalf of groups: "on behalf of the Group of African States",
  "on behalf of the Movement of Non-Aligned Countries", etc. — capture in `on_behalf_of`
- Names may include special characters: Kaludjerović, Benítez Versón, Segura Aragón

## Stage directions

Italic text throughout documents records procedural events, not speeches:

    The meeting was called to order at 3.30 p.m.
    It was so decided.
    The meeting was suspended at 4.35 p.m. and resumed at 5.15 p.m.
    The meeting rose at 5.20 p.m.
    Draft resolution A/64/L.72 was adopted (resolution 64/299).
    The members of the General Assembly observed a minute of silence.
    (spoke in English)       ← standalone language note

Stage directions must be stored in the database (see `stage_directions` table) because
the full procedural record must be preserved. Each stage direction records its position
in the document so the full meeting can be reconstructed in order.

## Votes

Two vote types occur in these records:

**1. Consensus vote** — signalled by "It was so decided." (no country list):

    May I take it that it is the wish of the General Assembly to adopt draft resolution A/76/L.85?
    Draft resolution A/76/L.85 was adopted (resolution 76/306).
    It was so decided.

When "It was so decided." is written, assume unanimous agreement; no country_votes rows.

**2. Recorded vote** — includes vote totals AND a per-country breakdown printed in the record:

    The draft resolution was adopted by 121 votes to 5, with 3 abstentions.

    In favour: Algeria, Angola, Argentina, ... (long list)
    Against: Israel, Marshall Islands, Micronesia, Nauru, United States of America
    Abstaining: Australia, Canada, Colombia, ...

The per-country lists ARE present inline in the verbatim record. Extract them as the
source for the `country_votes` table. The extraction pattern is:

    In favour:\s+(comma-separated country names)
    Against:\s+(comma-separated country names)
    Abstaining:\s+(comma-separated country names)

Each country name must then be normalised to UN official form via the `countries` lookup table.

## Explanation of vote / position

After adoption, speakers deliver "explanations of vote" or "explanations of position".
These are ordinary speeches that follow the adoption italic line.
The President introduces this section:

    The President: Before giving the floor to speakers in explanation of position on the
    resolution just adopted, may I remind delegations that explanations of vote are limited
    to 10 minutes and should be made by delegations from their seats.

# System architecture to build

The agent must implement this pipeline:

    PDF files
     ↓
    PDF text extraction (column-aware)
     ↓
    document structure detection
     ↓
    rule-based extraction
     ↓
    LLM semantic extraction
     ↓
    JSON validation
     ↓
    database storage

Key tools:

- PyMuPDF (`page.get_text("dict")` + `column_boxes()` from pymupdf-utilities) — PDF parsing
- Claude API (`claude-sonnet-4-6`) — semantic extraction
- PostgreSQL — storage
- un-scraper (`github.com/un-project/un-scraper`) — PDF acquisition (already used)

# Repository structure the agent should create

    data/
        raw_pdfs/
            en/ga/{session}/pv/document_{N}.pdf

    src/
        pdf/
            extract_text.py      # PyMuPDF, column-aware extraction
            clean_text.py        # strip headers, footers, page numbers

        structure/
            detect_sections.py   # segment into agenda items, speeches, votes

        extraction/
            metadata_extractor.py   # document symbol, meeting number, date, body
            speaker_extractor.py    # speaker name, country, language note, role
            vote_extractor.py       # adoption lines, counted votes if present

        llm/
            semantic_extractor.py   # agenda titles, resolution titles, country normalisation
            prompts.py

        validation/
            json_validator.py    # schema validation, retry logic

        db/
            models.py
            database.py

        pipeline/
            process_pdf.py       # single PDF → JSON
            batch_processor.py   # ThreadPoolExecutor over full dataset

    tests/
    configs/
    output/
        meeting_{N}.json

# Agent development phases

The agent should implement the system in 6 phases.

## Phase 1 — PDF ingestion

Goal: convert PDFs into clean text.

Tasks:

1. Implement column-aware text extraction using PyMuPDF.

   Use `page.get_text("dict")` (not plain `get_text()`) to obtain block/span-level data
   including bounding boxes and font flags.

   Use `column_boxes()` from `pymupdf-utilities` to obtain column bounding boxes in
   correct reading order (left column top-to-bottom, then right column top-to-bottom).
   Do not rely on PyMuPDF's default `sort=True` which reads across both columns.

   Per span, extract:
   - `span['flags'] & 0x10` → bold (speaker names)
   - `span['flags'] & 0x02` → italic (stage directions, adoption lines)
   - Supplement with `"Bold"` / `"Italic"` in `span['font']` as a fallback for
     malformed PDFs where font flags are incorrect.

2. Remove:
    - page numbers (plain integers at bottom, or `N/31` format)
    - running headers (document symbol and date repeated on each page)
    - footers (disclaimer text, document codes like `10-53066 (E)`)

3. Preserve bold and italic markers — they are semantically meaningful:
   - bold = speaker attribution
   - italic = stage direction or adoption line

4. Output normalised text, one file per PDF.

Validation:

input: 1 PDF
output: clean text file

Success criteria:

- text readable in reading order (left column then right column)
- no repeated headers or footers
- stage directions distinguishable from speech text

## Phase 2 — Document structure detection

Goal: detect logical sections.

Sections to detect:

    cover_page       → document symbol, meeting number, date, location, president
    agenda_item      → agenda item number, title, sub-item label
    draft_resolution → symbol, adoption status, resulting resolution number
    speech           → speaker, country, language note, text
    stage_direction  → italic procedural text
    closing          → meeting rose time

Detection strategy:

- Cover page: first page, extract symbol from header, meeting metadata from body
- Agenda items: bold text matching "Agenda item \d+" pattern
- Draft resolutions: bold "Draft resolution (A/..." or "Draft decision (A/..."
- Adoption lines: italic lines matching "Draft resolution .* was adopted"
- Speaker turns: bold names matching Name (Country): or Name (Country) (spoke in Language):
- Stage directions: italic text not matching adoption pattern
- Closing: italic "The meeting rose at ..."

Output example:

    {
      "symbol": "A/64/PV.121",
      "meeting_number": 121,
      "session": 64,
      "body": "GA",
      "date": "2010-09-13",
      "president": {"name": "Mr. Ali Abdussalam Treki", "country": "Libyan Arab Jamahiriya"},
      "agenda_items": [
        {
          "number": 13,
          "title": "Prevention of armed conflict",
          "sub_item": null,
          "continued": false
        }
      ],
      "speeches": [...],
      "resolutions": [...]
    }

Validation:

- run on all 3 sample PDFs
- verify sections look correct

## Phase 3 — Rule-based extraction

Goal: extract deterministic data without LLM.

### Metadata

Extract from cover page:

- document symbol: `A/{session}/PV.{N}` (top-right header)
- meeting number: ordinal integer from "Nth plenary meeting"
- session: integer from session name ("Sixty-fourth session" → 64) or from symbol
- body: GA or SC from symbol prefix
- date: ISO 8601 from "Weekday, DD Month YYYY, H p.m."
- location: "New York" or "Geneva"
- president: name and country from "President: Name ...... (Country)" line
- time called to order: from italic "The meeting was called to order at H.MM p.m."

### Speakers

Pattern:

    **Name** (Country):
    **Name** (Country) (*spoke in Language*):
    **The President** (*spoke in Language*):

Extract:

- speaker name (strip bold markers)
- country (may be None for titular roles)
- language spoken (may be None; English assumed if absent)
- speech text (everything until next speaker or stage direction)
- role: infer from name ("The President", "The Secretary-General") or None

### Votes

Two cases:

1. Consensus adoption — "It was so decided." follows the adoption line, no country list:
   Pattern: `Draft (?:resolution|decision) (A/\S+) was adopted \((resolution|decision) (\S+)\)\.`
   Extract: draft_symbol, adopted_symbol, vote_type=consensus

2. Recorded vote — vote totals followed by country lists:
   Pattern: `(\d+) (?:votes? )?in favour(?: to (\d+) against)?, with (\d+) abstentions?`
   Extract: yes_count, no_count, abstain_count, vote_type=recorded

   Then extract per-country positions from the lines that follow:
   Pattern: `^In favour:\s+(.+)$` → list of country names, vote_position=yes
   Pattern: `^Against:\s+(.+)$`   → list of country names, vote_position=no
   Pattern: `^Abstaining:\s+(.+)$` → list of country names, vote_position=abstain

   Country names are comma-separated and may wrap across lines.
   After extraction, each name must be looked up or created in the `countries` table.
   Use LLM normalisation if the name does not match exactly.

### Draft resolution adoption

Pattern: `Draft (?:resolution|decision) (A/\S+)(?:, as orally corrected,)? was adopted(?: \((resolution|decision) (\S+)\))?`

Extract:
- draft_symbol
- adopted_symbol (e.g. `64/299`)
- oral_correction: bool

## Phase 4 — LLM semantic extraction

Goal: extract ambiguous or complex information.

Agent builds prompts for:

- normalising agenda item titles (strip "(continued)", resolve sub-items)
- extracting resolution titles from bold text near the adoption line
- normalising country names to UN official form
  (e.g. "Bolivarian Republic of Venezuela" not just "Venezuela")
- inferring delegate role from context ("spoke on behalf of the Group of African States")
- handling edge cases in speaker attribution

Use:

Claude API (`claude-sonnet-4-6`) — preferred
OpenAI API or Mistral API — fallback

Agent must enforce:

    temperature = 0
    response format = JSON

Validation: ensure valid JSON on every response

## Phase 5 — JSON validation

Agent builds schema validator.

Schema:

    {
      "symbol": str,              # e.g. "A/64/PV.121"
      "body": "GA" | "SC",
      "session": int,
      "meeting_number": int,
      "date": str,                # ISO 8601
      "location": str,
      "president": {
        "name": str,
        "country": str | null
      },
      "agenda_items": [
        {
          "number": int,
          "sub_item": str | null,
          "title": str,
          "continued": bool
        }
      ],
      "resolutions": [
        {
          "draft_symbol": str,    # e.g. "A/64/L.72"
          "adopted_symbol": str | null,  # e.g. "64/299"
          "title": str | null,
          "vote_type": "consensus" | "recorded",
          "yes_count": int | null,
          "no_count": int | null,
          "abstain_count": int | null
        }
      ],
      "speeches": [
        {
          "position": int,
          "speaker": str,
          "country": str | null,
          "language": str | null,
          "role": str | null,
          "on_behalf_of": str | null,
          "text": str
        }
      ],
      "stage_directions": [
        {
          "position": int,
          "text": str,
          "direction_type": str
        }
      ]
    }

Validation rules:

- `symbol` must match `[AS]/\d+/PV\.\d+`
- `date` must be valid ISO 8601
- `meeting_number` and `session` must be positive integers
- no missing required fields
- `yes_count`, `no_count`, `abstain_count` must be integers when `vote_type = "recorded"`

On failure:

retry extraction (rule-based first, then LLM)
if still failing: flag for manual review, write to `output/failed/`

## Phase 6 — Database integration

Agent builds PostgreSQL schema.

### Countries Table

Never store country names directly in vote tables.

    countries
    ---------
    id (PK)
    name            # exact UN official name
    short_name
    iso2
    iso3
    un_member_since

Example name: "United Kingdom of Great Britain and Northern Ireland"

### Speakers Table

All speakers are stored, regardless of whether they have a country affiliation.

    speakers
    --------
    id (PK)
    name
    country_id (FK → countries, nullable)   # null for President, SG, Secretariat staff
    role            # "Representative", "Delegate", "President", "Secretary-General", etc.
    title           # "Mr.", "Mrs.", "Ms.", "H.E.", etc.

### Documents Table

    documents
    ---------
    id (PK)
    symbol          # e.g. "A/64/PV.121"
    body            # "GA" or "SC"
    meeting_number
    session
    date
    location
    pdf_path        # relative path within data/raw_pdfs/

### Stage Directions Table

Stores all procedural italic text in document order alongside speeches.
Together with the speeches table, these two tables allow full reconstruction of
a meeting's proceedings in sequence using `position_in_document`.

    stage_directions
    ----------------
    id (PK)
    document_id (FK → documents)
    text            # full italic text
    direction_type  # "adoption" | "decision" | "suspension" | "resumption"
                    # | "adjournment" | "silence" | "language_note" | "other"
    position_in_document

### Speeches Table

    speeches
    --------
    id (PK)
    document_id (FK → documents)
    speaker_id (FK → speakers)
    language        # language spoken (null = English)
    on_behalf_of    # group name if speaking on behalf of a bloc
    text
    position_in_document

### Resolutions Table

    resolutions
    -----------
    id (PK)
    draft_symbol    # e.g. "A/64/L.72"
    adopted_symbol  # e.g. "64/299" (null if not adopted in this document)
    title
    body            # "GA" or "SC"
    session
    category        # LLM-assigned topic tag

### Votes Table

    votes
    -----
    id (PK)
    document_id (FK → documents)
    resolution_id (FK → resolutions)
    vote_type       # "consensus" | "recorded"
    vote_scope      # "whole_resolution" | "paragraph" | "amendment"
    paragraph_number
    yes_count
    no_count
    abstain_count

### Country Votes Table

Stores individual country positions for recorded (non-consensus) votes.
These are NOT present in PV verbatim records; they come from summary records or annexes.

    country_votes
    -------------
    vote_id (FK → votes)
    country_id (FK → countries)
    vote_position   # "yes" | "no" | "abstain" | "absent"

### Amendments Table (optional)

    amendments
    ----------
    id (PK)
    resolution_id (FK → resolutions)
    description
    proposed_by_country_id (FK → countries)

### Example query

How often does the US vote against resolutions on Palestine?

    SELECT COUNT(*)
    FROM country_votes cv
    JOIN votes v ON cv.vote_id = v.id
    JOIN resolutions r ON v.resolution_id = r.id
    JOIN countries c ON cv.country_id = c.id
    WHERE c.iso2 = 'US'
    AND cv.vote_position = 'no'
    AND r.category = 'Palestinian conflict'

# Batch processing

Agent implements parallel processing.

    from concurrent.futures import ThreadPoolExecutor

    def process_batch(pdf_paths, max_workers=8):
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(process_pdf, pdf_paths)

Target: 8000 PDFs processed in under 1 hour.
LLM calls are the bottleneck — batch where possible and cache results.

# Automatic evaluation

Agent must build evaluation tools.

Metrics:

- metadata accuracy (symbol, date, session, meeting number)
- speaker detection accuracy (name, country match)
- resolution extraction accuracy (symbol, vote type)
- agenda item title accuracy

Evaluation dataset:

100 manually verified PDFs stored in `tests/fixtures/`

# Error recovery

    if rule_based_extraction_fails:
        retry with LLM

    if llm_extraction_fails:
        flag for manual review → write to output/failed/{symbol}.pdf

Error log must record: PDF path, phase failed, error message, timestamp.

# Final deliverables

## CLI tool

    python process_dataset.py data/raw_pdfs/

## Output format

JSON files:

    output/
        meeting_A_64_PV_121.json
        meeting_A_76_PV_102.json
        failed/
            meeting_X.json   # with error metadata

## Database importer

    python import_json_to_db.py output/
