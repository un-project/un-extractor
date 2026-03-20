# TODO

Open tasks and known limitations for the un-extractor pipeline.

---

## Extraction accuracy

- [ ] **`unknown` draft symbol (remaining)** — A handful of adoption lines ("The draft
  decision was adopted.") appear with no preceding bold header and no parenthetical symbol,
  so the draft symbol cannot be resolved. These are typically procedural decisions that
  don't correspond to a numbered draft. Consider skipping resolution creation for these
  cases rather than storing `draft_symbol = "unknown"`.

- [x] **Resolution symbol leaks across agenda items** — `_last_resolution_header_text` is
  now cleared inside `_flush_and_start`, preventing a symbol from a prior agenda item's
  resolution header from being attributed to an adoption line with no symbol in the next item.

- [x] **Country list detection misses indented headers** — Added `\s*` after the
  `(?:^|\n)` anchor in all three header patterns, matching the existing `_VOTE_SECTION_STOP_RE`
  which already used `\n\s*`. Test added for blocks with a leading space.

- [x] **Vote totals "votes" keyword** — `_VOTE_TOTALS_RE` already has `(?:votes?\s+)?`
  as an optional group, so "by 121 to 5" was always matched. Added explicit test cases
  for the short form with and without abstentions to pin the behavior.

- [ ] **Agenda continuation items not split correctly** — `_AGENDA_RE` matches "Agenda
  item 13" but not "Agenda item 13 (continued)" when "(continued)" is part of the same
  block. These items get merged into the previous item instead of starting a new one.
  Extend the regex and set `continued=True` when matched.

- [ ] **Smart-quote mismatch in title extraction** — `_ENTITLED_RE` defines separate
  `_OPEN_QUOTE` / `_CLOSE_QUOTE` character classes. Mismatched typographic quotes
  (e.g., `\u201c` opened, `'` closed) fail to match. Accept any quote-like character for
  closing if the title is otherwise plausible.

---

## Metadata

- [ ] **Security Council documents** — Symbol prefix `S/PV.NNNN` is supported by the
  regex but no SC PDFs are in the sample set. Validate against at least one SC document.
  SC symbols have no session component; `extract_session` should return `None` explicitly
  for the `S/` prefix rather than silently falling through.

- [x] **Date year range validation** — `extract_date` now rejects years outside
  1945–2100, returning `None` for implausible OCR artifacts instead of propagating them
  to `validate_record`.

- [ ] **Location extraction false positives** — `extract_location` searches all text, so
  delegates mentioning "New York" in speeches can trigger a match outside the cover page.
  Restrict the search to cover-page blocks (or the first ~10 blocks of the document).

---

## Pipeline robustness

- [ ] **Retry on LLM failure** — The LLM enrichment phase catches all exceptions and logs
  a warning, but does not retry. Add a simple exponential backoff (1–2 retries) for
  transient API errors.

- [ ] **Batch worker crash propagation** — If a thread in `ThreadPoolExecutor` raises an
  exception that escapes `_process_one` (e.g., an unexpected PyMuPDF crash), calling
  `future.result()` re-raises it and halts the entire batch. Wrap `future.result()` in a
  try/except so unexpected crashes are recorded as failures rather than killing the run.

- [x] **Batch failure report deduplication** — Resolved: error filenames are now derived
  from the PDF's path relative to `root_dir` (e.g., `en_ga_64_pv_document_121_error.json`)
  so PDFs from different sessions with the same stem no longer overwrite each other.

---

## Database

- [ ] **Amendment table population** — `src/db/models.py` defines the `amendments` table
  but `import_json_to_db.py` does not populate it yet. Wire up amendment import when the
  extractor starts producing amendment records.

- [ ] **Atomic import per document** — If `import_record` partially inserts rows and then
  fails (e.g., resolution FK violation), the partial data is committed. Wrap each document
  import in a single transaction with a full rollback on any exception.

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

## Testing

- [ ] **Security Council integration test** — Add at least one SC PDF (`S/PV.*`) and a
  matching fixture to prevent regressions in SC-specific paths (no session, different
  symbol format).

- [ ] **Vote extraction edge cases** — Add unit tests for: vote totals without the "votes"
  keyword; "In favour:" with leading whitespace; country names duplicated across positions;
  amendment votes (should not inherit country lists from the parent resolution vote).

- [x] **Database import tests** — `tests/test_import_json_to_db.py` added: first import,
  idempotent re-import, `--recreate`, resolution sharing, country/speaker deduplication,
  and partial-failure rollback, all using an in-memory SQLite database.

---

## Documentation

- [ ] **LLM enrichment walkthrough** — Add a section to README.md showing a concrete
  example of running with `--llm` and what fields it populates vs. rule-based extraction.
