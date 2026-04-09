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

- [x] **SC draft resolution texts + co-sponsorship (UNBench)** —
  `scripts/import_unbench_sc_drafts.py` processes UNBench JSON files and
  populates `resolutions.draft_text` (new column) and the new
  `resolution_sponsors (resolution_id, country_id, country_name)` table.
  Creates stub `resolutions` rows for rejected/vetoed drafts not in the DB.
  Full dataset (~3,000 drafts, 1994–2024) requires manual download from
  Google Drive (see https://github.com/yueqingliang1/UNBench).  Use
  ``--sample`` to run against the 30-file GitHub subset without downloading.
  Tested: 30 drafts, 308 sponsor rows (300/308 country_id matched).


- [x] **Extraction coverage report** — `scripts/coverage_report.py` prints
  per-body/session counts of extracted vs. stub-only documents.  Supports
  `--body GA/SC`, `--csv FILE`, `--db URL`.  A document is counted as
  *extracted* when it has at least one row in `speeches`.

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

- [x] **Import Voeten resolution-level metadata (importantvote + issue codes)** —
  `scripts/import_voeten_resolution_meta.py` downloads `roll_calls.csv` and
  `issues.csv` from the TidyTuesday / unvotes package (Voeten et al., CC0)
  and populates 7 new BOOLEAN columns on `resolutions`: `important_vote` and
  `issue_me/nu/co/hr/ec/di`.  Coverage: 4,149 of 6,202 roll calls matched
  (1946–2019); 347 important votes; issue counts: me=896, nu=580, co=564,
  hr=773, ec=492, di=779.  Cached in `data/voeten/`.

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
