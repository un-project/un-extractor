# TODO

Open tasks and known limitations for the un-extractor pipeline.

---

## Extraction accuracy

- [ ] **Scanned-document country vote lists** — Older OCR documents (1970s–1980s) sometimes
  have country names in vote lists split across lines with hyphen-space breaks (e.g.
  `"Ar- gentina"`). The hyphen-space collapse in `normalize_country_name` handles most cases,
  but multi-word names split mid-word (e.g. `"United King- dom"`) may still fail. Audit the
  oldest sessions after a full pipeline rerun.

---

## Pipeline robustness

- [ ] **Retry on LLM failure** — The LLM enrichment phase catches all exceptions and logs
  a warning, but does not retry. Add a simple exponential backoff (1–2 retries) for
  transient API errors.

---

## Database

- [ ] **Amendment table population** — `src/db/models.py` defines the `amendments` table
  but `import_json_to_db.py` does not populate it yet. ~40 % of amendment-related stage
  directions have no document symbol (oral amendments, context-dependent references), so
  extraction would silently miss most records. Additionally `resolution_id` is non-nullable,
  making it impossible to store oral/undocumented amendments. Defer until the schema is
  relaxed and the extractor handles contextual resolution references.

- [ ] **Concurrent import race condition** — Running two importer processes against the
  same database simultaneously can create duplicate rows (both read "symbol not present"
  before either writes). Use `INSERT … ON CONFLICT DO NOTHING` or a PostgreSQL advisory
  lock keyed on the document symbol.

- [ ] **Speaker deduplication ignores language** — The deduplication key is `(name, country_id,
  organization)`. A delegate who speaks in both English and French is treated as the same
  speaker, which is correct; but two different delegates with the same name from the same
  country are silently merged. Consider adding a secondary check on first-seen meeting date
  or exposing duplicates as a data-quality report.

---

## Website data enrichment

These items produce data that the un-project.org website is already
structured to consume but that the pipeline does not yet extract.

- [ ] **Co-sponsorship extraction** — Speeches frequently contain lines like
  "The following countries are co-sponsors of draft resolution A/64/L.72: …"
  or "I also speak on behalf of …" followed by a country list.  Extracting
  these would populate a new `resolution_sponsors (resolution_id, country_id)`
  table, enabling a co-sponsor list on the resolution detail page and
  co-sponsorship-based country clustering on the website.

- [ ] **Resolution symbol mentions in speeches** — Speeches routinely cite
  resolution symbols in their text (e.g. "resolution 64/299", "draft resolution
  A/64/L.72").  A regex pass over `speeches.text` could populate a
  `speech_resolution_mentions (speech_id, resolution_id)` table, enabling an
  "Speeches about this resolution" section on the resolution detail page and a
  "Resolutions discussed in this speech" annotation on speaker/country profiles.

- [ ] **Explanation-of-vote tagging** — In recorded-vote meetings, delegates
  often give a short speech immediately before or after the vote to explain their
  position.  These could be tagged (e.g. a `speech_type` enum: `substantive`,
  `explanation_of_vote`, `procedural`) and surfaced as a dedicated section on
  the resolution detail page — the most policy-relevant content about any vote.

- [ ] **SC draft resolution texts (UNBench)** — The UNBench dataset
  (https://github.com/yueqingliang1/UNBench, MIT license) includes full texts
  of SC draft resolutions (1994–2024) in JSON format, including *rejected*
  drafts that never became resolutions and are therefore absent from the UNDL
  voting CSV.  The JSON `ID` field maps to `resolutions.draft_symbol`
  (e.g. `S/2023/970`).  The full dataset is on Google Drive (linked in the
  README); the 30-sample repo subset confirms the schema.  If the full dataset
  is accessible, import draft texts into a new `resolutions.draft_text TEXT`
  column.  This also enables the co-sponsorship item below since the JSON
  includes an `Authors` list per draft.

- [ ] **Co-sponsorship from UNBench drafts** — Each UNBench draft JSON has an
  `Authors` list of sponsoring countries.  Once draft texts are imported,
  extract these into a `resolution_sponsors (resolution_id, country_id)` table.
  This is complementary to the speech-based co-sponsorship extraction (which
  covers GA and older SC sessions not in UNBench).

- [ ] **GA resolution full text** — CR-UNSC covers only SC resolutions.  GA
  resolution texts are available via the UN Digital Library OAI-PMH or
  undocs.org.  Fetching and storing them in `resolutions.full_text` would extend
  full-text search and the resolution detail page to the full GA dataset (~4,000
  adopted resolutions).

- [ ] **Extraction coverage report** — The DB contains thousands of stub
  `documents` rows (created by `import_undl_votes.py`) for meetings not yet
  extracted from PDF.  A script (or `--report` flag on `import_json_to_db.py`)
  that prints per-body/session counts of extracted vs. stub-only documents
  would make it easy to see which sessions are still missing speech content
  and prioritise PDF processing.

- [ ] **Website: Ambassador profiles** — The `permanent_representatives` and
  `sc_representatives` tables are populated.  The website needs a
  "Representatives" tab on country profiles showing who represented the country
  and when, with links to their UNDL record.  The tab header already appears
  in country profiles (e.g. un-project.org/country/USA/) but the content is
  not yet rendered.

---

## Voting analytics & geopolitics

The UNDL voting CSVs (already imported: ~947k GA rows, ~41k SC rows) provide
a complete `(country, resolution, vote_position, date)` record from 1946–2026
that is sufficient for the following analytical features.

- [ ] **Import Voeten resolution-level metadata (importantvote + issue codes)** —
  The Voeten et al. dataset (doi:10.7910/DVN/LEJUQZ) includes two resolution-level
  variables not in the UNDL CSV that would meaningfully enrich the DB:

  - `importantvote` (0/1): high-salience votes, widely used in IR research to
    filter out procedural/routine resolutions.  Add `resolutions.important_vote
    BOOLEAN` and populate it.  Enables the website to highlight significant votes
    and lets researchers exclude routine votes from analysis.

  - Issue area flags (6 binary columns per resolution):
    `me` (Palestine/Israel), `nu` (nuclear weapons), `co` (colonialism),
    `hr` (human rights), `ec` (economic development), `di` (arms control).
    Add `resolutions.issue_me`, `issue_nu`, `issue_co`, `issue_hr`, `issue_ec`,
    `issue_di` BOOLEAN columns.  Enables issue-specific ideal point estimation
    (e.g. ideal points on human rights votes only) and issue-based filtering on
    the website.

  Requires downloading the Voeten dataset separately (different file from the
  UNDL CSV) and a new `scripts/import_voeten_resolution_meta.py` script.
  Matching key: join via `rcid` + `session` or via `adopted_symbol`.
  Run after `import_undl_votes.py`.

- [ ] **Data-driven bloc detection** — Compute a pairwise voting-agreement
  matrix per year and apply hierarchical or spectral clustering to recover
  voting blocs automatically, rather than the hardcoded `coalitions.py` list
  in the website.  Store results in a `voting_blocs (country_id, year, bloc)`
  table.  Use rolling 5-year windows to detect gradual realignments.

- [ ] **Vote prediction model** — Train a gradient-boosting classifier to
  predict a country's vote (yes/no/abstain) on a resolution given: the
  country's recent ideal point, resolution category/subjects, and sponsoring
  region.  Useful both as a research tool and for flagging anomalous votes
  (country broke from expected pattern).

---

## Documentation

- [ ] **LLM enrichment walkthrough** — Add a section to README.md showing a concrete
  example of running with `--llm` and what fields it populates vs. rule-based extraction.
