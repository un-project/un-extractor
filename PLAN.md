# Agent mission

Goal:

    Build a scalable pipeline that converts UN meeting PDFs into structured JSON and stores them in a database.

Target dataset:

- ~8000 PDFs
- ~30 pages each
- Sources: meetings of the United Nations, especially
    - United Nations General Assembly
    - United Nations Security Council

# System architecture to build

The agent must implement this pipeline:

    PDF files
     ↓
    PDF text extraction
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

- PyMuPDF — PDF parsing
- OpenAI API or Mistral API — semantic extraction
- PostgreSQL — storage

# Repository structure the agent should create

    un-meeting-parser/
    
    data/
        raw_pdfs/
    
    src/
        pdf/
            extract_text.py
            clean_text.py
    
        structure/
            detect_sections.py
    
        extraction/
            metadata_extractor.py
            speaker_extractor.py
            vote_extractor.py
    
        llm/
            semantic_extractor.py
            prompts.py
    
        validation/
            json_validator.py
    
        db/
            models.py
            database.py
    
        pipeline/
            process_pdf.py
            batch_processor.py
    
    tests/
    configs/

# Agent development phases

The agent should implement the system in 6 phases.

## Phase 1 — PDF ingestion

Goal: convert PDFs into clean text.

Tasks:

1. Implement text extraction using PyMuPDF.

2. Remove:
    - page numbers
    - headers
    - footers

3. Output normalized text.

Validation:

input: 1 PDF
output: clean text file

Success criteria:

- text readable
- no repeated headers

## Phase 2 — Document structure detection

Goal: detect logical sections.

Sections to detect:

    header
    agenda
    speeches
    votes
    closing

Agent must:

- Implement keyword detection
- Segment the document

Output example:

    {
     "header": "...",
     "agenda": "...",
     "speeches": "...",
     "votes": "..."
    }

Validation:

- run on 10 PDFs
- verify sections look correct

## Phase 3 — Rule-based extraction

Goal: extract deterministic data without LLM.

Agent implements regex extractors for:

### Metadata

Extract:

- meeting number
- session
- date
- body

Example:

9453rd meeting
New York, Monday, 15 March 2025

### Speakers

Detect patterns like:

Mr. Zhang (China):

Extract:

- speaker
- country
- speech text

### Votes

Detect patterns:

14 votes to 0, with 1 abstention
121 in favour to 5 against

Extract:

- yes
- no
- abstain
- resolution symbol

## Phase 4 — LLM semantic extraction

Goal: extract ambiguous information.

Agent builds prompts for:

- agenda titles
- resolution titles
- normalization of country names

Use:

OpenAI API or Mistral API

Agent must enforce:

    temperature = 0
    JSON output

Validation: ensure valid JSON

## Phase 5 — JSON validation

Agent builds schema validator.

Schema example:

{
 meeting:
   body
   session
   meeting_number
   date

 speeches:
   speaker
   country
   role
   text

 resolutions:
   symbol
   vote
}

Validation rules:

- no missing required fields
- valid JSON
- numeric votes

On failure:

retry extraction

## Phase 6 — Database integration

Agent builds PostgreSQL schema.

### Countries Table

You should never store country names directly in vote tables.

Instead:

    countries
    ---------
    id (PK)
    name
    short_name
    iso2
    iso3
    un_member_since

Important: keep the exact UN name.

Example:

United Kingdom of Great Britain and Northern Ireland

### Speakers Table

Each speech in the record has a speaker.

    speakers
    --------
    id (PK)
    name
    country_id (FK)
    role
    title

Example:
id	name	country_id	role
1	Mr. Cunningham	USA	Representative
2	Ms. Dubois	FRA	Delegate

This allows queries like:

show all speeches by US delegates

### Documents Table

Each PDF corresponds to a meeting record.

    documents
    ---------
    id (PK)
    symbol
    meeting_number
    session
    date
    pdf_url

Example:

A/58/PV.73

### Speeches Table

Each speech segment in the meeting.

    speeches
    --------
    id (PK)
    document_id (FK)
    speaker_id (FK)
    text
    position_in_document

### Resolutions Table

    resolutions
    -----------
    id (PK)
    symbol
    title
    category

Example:

A/58/L.47

### Votes Table

Each voting event.

    votes
    -----
    id (PK)
    document_id (FK)
    resolution_id (FK)

    vote_scope
        whole_resolution
        paragraph
        amendment
    
    paragraph_type
    paragraph_number
    
    is_amendment_vote
    
    yes_count
    no_count
    abstain_count

### Country Votes Table

This table stores every country's position.

    country_votes
    -------------
    vote_id (FK)
    country_id (FK)
    vote_position

### Amendments Table (Optional but Useful)

    amendments
    ----------
    id (PK)
    resolution_id
    description
    proposed_by_country_id

### Example Query You Will Want

Example: How often does the US vote against resolutions on Palestine?

SELECT *
FROM country_votes
JOIN votes
JOIN resolutions
WHERE country_id = USA
AND vote_position = 'no'
AND category = 'Palestinian conflict'

# Batch processing

Agent implements parallel processing.

Example:

ThreadPoolExecutor

Processing pipeline:

for pdf in dataset:
    process_pdf(pdf)

Target:

8000 PDFs < 1 hour

# Automatic evaluation

Agent must build evaluation tools.

Metrics:

speaker detection accuracy
vote extraction accuracy
metadata accuracy

Evaluation dataset:

100 manually verified PDFs

# Error recovery

Agent must implement retry logic:

if extraction fails:
    retry with LLM

If still failing:

flag for manual review

# Final deliverables

Agent must produce:
Code

Full pipeline implementation.
CLI tool

Example usage:

python process_dataset.py data/raw_pdfs/

Output format

JSON files:

output/
    meeting_9453.json

Database importer

python import_json_to_db.py
