# TODO

Open tasks and known limitations for the un-extractor pipeline.

---

## Extraction accuracy

- [ ] **Smart-quote mismatch in title extraction** — `_ENTITLED_RE` defines separate
  `_OPEN_QUOTE` / `_CLOSE_QUOTE` character classes. Mismatched typographic quotes
  (e.g., `\u201c` opened, `'` closed) fail to match. Accept any quote-like character for
  closing if the title is otherwise plausible.

---

## Metadata

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

## Testing

- [ ] **Security Council integration test** — Add a golden fixture for `S/PV.8422`
  covering: session=None, president, SC adoption pattern, vote totals, and country votes.

---

## Documentation

- [ ] **LLM enrichment walkthrough** — Add a section to README.md showing a concrete
  example of running with `--llm` and what fields it populates vs. rule-based extraction.
