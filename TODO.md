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

## Metadata

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

## Country data quality

- [x] **Automate post-import cleanup** — `fix_country_duplicates.py` is now called
  automatically at the end of `import_json_to_db.py` and `import_undl_votes.py`.

- [x] **Data quality report** — `fix_country_duplicates.py --report` prints a
  three-section summary: countries with no iso3 (sorted by speech+vote usage),
  unrecognised names that are candidates for new alias entries, and official member
  states missing an iso3 code.

- [x] **Detect new garbled names automatically** — `fix_country_duplicates.py --report`
  section 4 applies four heuristics (short ≤5 chars, starts-non-letter, has-digit, long
  >40 chars) to no-iso3 rows and prints each row with its triggered flags, so new OCR
  artifacts are visible without scanning the full list.

---

## Testing

- [x] **Tests for `fix_country_duplicates.py`** — 20 unit tests in
  `tests/test_fix_country_duplicates.py` cover: rename in-place, merge with iso3
  transfer, merge where canonical already has iso3, speaker move/deduplication,
  country-vote move/deduplication, all junk-deletion cases, savepoint rollback on
  error, and the `--dry-run` flag.

- [x] **Tests for `normalize_country_name`** — `tests/test_normalize_country_name.py`
  parametrises over every `_ALIASES` entry (295 cases auto-derived from the table) plus
  20 tests for preprocessing (hyphen-space collapse, ALL-CAPS, \x08 artefacts, leading
  punctuation, trailing procedural text) and edge cases.

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

- [ ] **Subject taxonomy normalisation** — `resolutions.category` is populated
  from the UNDL CSV but contains inconsistent free-text strings.  Building a
  controlled mapping (similar to `country_aliases.py`) from raw UNDL subject
  strings to a small canonical set would enable reliable topic-based filtering
  and browsing on the website.

---

## CR-UNSC integration

- [x] **Verify CR-UNSC filename conventions** — Confirmed via zip central
  directory (HTTP range request, no full download): all 2742 files follow
  `S_RES_NNNN_YYYY_MeetingRec_EN.pdf` (resolution-indexed, not PV-indexed).
  Regex and dest path updated accordingly; files land at
  `sc/{year}/pv/document_rNNNN.pdf`.

- [x] **GraphML node format** — Confirmed: nodes carry `<data key="v_symbol">`
  with the full UNDL symbol; edges carry `<data key="e_weight">`.  Parser
  updated accordingly.

- [x] **Run import pipeline end-to-end** — Completed: 14,157 citation edges
  inserted; `full_text` populated for matching SC resolutions.

- [x] **Back-fill `cited_id` for GA resolutions** — `_build_symbol_index`
  now indexes all resolutions (SC + GA).  For GA rows stored without the
  `A/RES/` prefix (e.g. `"64/293"`), a prefixed alias (`"A/RES/64/293"`)
  is added so CR-UNSC GraphML symbols resolve correctly.

---

## DHL supplementary datasets

- [x] **UN Member States** — `scripts/import_undl_member_states.py` enriches
  `countries` with `m49`, `un_member_since`, and `un_member_end` from the DHL
  Member States CSV.

- [x] **GA Resolution metadata** — `scripts/import_undl_ga_resolutions.py`
  upserts title, subjects, agenda_title, committee_report, undl_id, and
  undl_link for all 20,761 GA resolutions (including consensus ones absent
  from the voting CSV).

- [x] **Permanent Representatives & SC Representatives** —
  `scripts/import_undl_representatives.py` populates `permanent_representatives`
  and `sc_representatives` tables with historical ambassador and SC delegate
  records; best-effort speaker matching by last name.

- [ ] **Speaker matching quality (representatives)** — After running
  `import_undl_representatives.py`, check how many rows still have
  `speaker_id = NULL`.  Improve matching by also trying salutation + last name
  and by expanding the search to alternative names.

- [x] **UN Thesaurus (UNBIS)** — `src/extraction/unbis_subjects.py` provides
  `classify_unbis(subjects)` mapping raw pipe-separated DHL subject strings
  to one of 18 canonical UNBIS scheme names (e.g. "POLITICAL AND LEGAL
  QUESTIONS").  Generated by `scripts/generate_unbis_mapping.py` from the
  UNBIS SKOS/Turtle file (7,245 English label mappings, 18 schemes).
  Prerequisite for the subject taxonomy normalisation TODO item: the
  `classify_unbis()` function replaces the hand-coded keyword rules in
  `vote_categories.py` once alias coverage is sufficient.

- [ ] **Website: Ambassador profiles** — The `permanent_representatives` and
  `sc_representatives` tables enable an "Ambassador" tab on country profiles
  showing who represented the country and when, with links to their UNDL
  record.

---

## General Debate speeches

- [x] **Import General Debate metadata** — `scripts/import_undl_general_debate.py`
  downloads the DHL General Debate dataset (sessions 1–79, 1946–2024) and
  populates `general_debate_entries` + sets `documents.is_general_debate`.

- [ ] **Speaker matching quality** — The script matches speakers by last-name
  suffix against the `speakers` table.  After a full run, check how many
  `general_debate_entries` rows still have `speaker_id = NULL` and improve the
  matching heuristic (e.g. try salutation + last name, or fuzzy match).

- [ ] **General Debate full-text corpus** — The DHL dataset is metadata only.
  The UN General Debate Corpus (Baturo et al., sessions 1–74) provides full
  speech text and is freely available on Harvard Dataverse.  Importing it would
  populate `speeches.text` for General Debate speeches not yet extracted from
  PDF and enable full-text search over high-level policy statements.

- [x] **SC Debates corpus (Schönfeld et al.)** — `scripts/import_sc_debates.py`.
  Harvard Dataverse, CC0,
  doi:10.7910/DVN/KGVSYH (v6.1, Feb 2025).  106,302 SC speeches from
  6,233 meetings, 1995–2020.  Files: `meta.tsv` (meeting metadata),
  `speaker.tsv` (speech-level metadata), `speeches.tar` (one .txt per
  speech).  Meeting symbols (`S/PV.XXXX`) map directly to `documents.symbol`;
  importing would bulk-populate `speeches.text` for SC meetings not yet
  processed from PDF — covering 25 years without the 2.1 GB PDF download.
  Strictly preferable to `import_crUnsc_pdfs.py` for the 1995–2020 window.
  Reference: https://arxiv.org/abs/1906.10969

- [ ] **Website: General Debate section** — Add a `/debate/` section to the
  website that lists each session's General Debate with speakers per country,
  their salutation, and a link to the UNDL speech document.  Enabled by the
  `general_debate_entries` table and `documents.is_general_debate` flag.

---

## Voting analytics & geopolitics

The UNDL voting CSVs (already imported: ~947k GA rows, ~41k SC rows) provide
a complete `(country, resolution, vote_position, date)` record from 1946–2026
that is sufficient for the following analytical features.

- [ ] **Ideal point estimation** — Implement the Bailey, Strezhnev & Voeten
  (2017) Bayesian IRT model to place every country on a latent policy dimension
  (roughly: liberal-Western ↔ non-aligned) per year.  Their replication code is
  public and uses exactly the same UNDL data.  Output: a new
  `country_ideal_points (country_id, year, ideal_point, se)` table that the
  website can use for a richer voting-similarity map and country profiles.
  Reference: https://doi.org/10.1017/S0022381617000931

- [ ] **Data-driven bloc detection** — Compute a pairwise voting-agreement
  matrix per year and apply hierarchical or spectral clustering to recover
  voting blocs automatically, rather than the hardcoded `coalitions.py` list
  in the website.  Store results in a `voting_blocs (country_id, year, bloc)`
  table.  Use rolling 5-year windows to detect gradual realignments.

- [ ] **Alignment time series** — For each country pair, compute yearly
  agreement rate → time series.  Store in a `country_alignment_series
  (country_id_a, country_id_b, year, agreement_rate)` table.  Enables the
  website to show a chart of how any two countries' voting alignment has
  evolved, and to surface inflection points (e.g. post-1991, post-2022
  Ukraine fractures).

- [ ] **Vote prediction model** — Train a gradient-boosting classifier to
  predict a country's vote (yes/no/abstain) on a resolution given: the
  country's recent ideal point, resolution category/subjects, and sponsoring
  region.  Useful both as a research tool and for flagging anomalous votes
  (country broke from expected pattern).

- [ ] **P5 veto tracking** — SC vetoed draft resolutions never become
  resolutions, so they are absent from the UNDL CSV.  They are documented in
  the UN Journal and the Security Council Report.  A separate scraper/import
  for veto data would complete the SC picture and enable veto-pattern analysis
  on the website.

---

## Documentation

- [ ] **LLM enrichment walkthrough** — Add a section to README.md showing a concrete
  example of running with `--llm` and what fields it populates vs. rule-based extraction.
