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

- [ ] **Automate post-import cleanup** — `fix_country_duplicates.py` should be called
  automatically at the end of `import_json_to_db.py` and `import_undl_votes.py` rather than
  as a separate manual step.

- [ ] **Data quality report** — Add a script (or a `--report` flag to `fix_country_duplicates.py`)
  that prints a summary of remaining issues: countries with no iso3, countries whose name
  does not match any known alias pattern, and iso3 codes missing from the `countries` table.
  This would make it easier to discover new garbled forms after each pipeline rerun without
  browsing the full country list in the web UI.

- [ ] **Detect new garbled names automatically** — After a full pipeline rerun the database
  typically accumulates hundreds of new country rows with no iso3. A heuristic scan
  (short names, non-letter start, names containing digits, names >40 chars) could flag
  candidates for review and alias addition without needing manual inspection of the full list.

---

## Testing

- [ ] **Tests for `fix_country_duplicates.py`** — The migration script has no unit tests.
  Add tests covering: merge with iso3 transfer, merge where canonical already has iso3,
  junk row deletion, savepoint rollback on error, and the `--dry-run` flag.

- [ ] **Tests for `normalize_country_name`** — The alias table has grown significantly.
  Add a parametrised test suite that asserts the expected canonical name for each alias
  key, so regressions are caught immediately when aliases are added or removed.

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

- [ ] **Verify CR-UNSC filename conventions** — `import_crUnsc_pdfs.py`
  assumes filenames of the form `S-PV-NNNN_YYYY-MM-DD.pdf`.  Confirm against
  the actual zip contents on first run; update the regex if the convention
  differs.  (Text and GraphML filenames have been confirmed and are correct.)

- [x] **GraphML node format** — Confirmed: nodes carry `<data key="v_symbol">`
  with the full UNDL symbol; edges carry `<data key="e_weight">`.  Parser
  updated accordingly.

- [x] **Run import pipeline end-to-end** — Completed: 14,157 citation edges
  inserted; `full_text` populated for matching SC resolutions.

- [ ] **Back-fill `cited_id` for GA resolutions** — The citation network
  includes GA resolution citations.  Currently only SC resolutions are
  indexed in `_build_symbol_index`.  Extend if GA-citation resolution of
  `cited_id` is needed.

---

## Documentation

- [ ] **LLM enrichment walkthrough** — Add a section to README.md showing a concrete
  example of running with `--llm` and what fields it populates vs. rule-based extraction.
