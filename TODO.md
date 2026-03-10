# TODO

Open tasks and known limitations for the un-extractor2 pipeline.

---

## Extraction accuracy

- [ ] **`unknown` draft symbol** — Some adoption lines match the adoption regex but no
  capture group provides a draft symbol (e.g. "The draft decision was adopted." without a
  parenthetical). Consider extracting the symbol from a preceding bold "Draft decision
  (A/…)" header block and linking it to the adoption line.

- [ ] **Roman-numeral resolution symbol validation** — The JSON validator flags Roman
  numerals (I, II … XIX) as unexpected `draft_symbol` format. Update the validator to
  accept Roman numerals as valid draft symbols when no `A/…` symbol is available.

---

## Metadata

- [ ] **Security Council documents** — Symbol prefix `S/PV.NNNN` is supported by the
  regex but no SC PDFs are in the sample set. Validate against at least one SC document.

---

## Pipeline robustness

- [ ] **Retry on LLM failure** — The LLM enrichment phase catches all exceptions and logs
  a warning, but does not retry. Add a simple exponential backoff (1–2 retries) for
  transient API errors.

- [ ] **Batch failure report deduplication** — Running `process_batch` twice on the same
  directory can produce duplicate `_error.json` files. Use a timestamp in the filename or
  overwrite deterministically.

---

## Database

- [ ] **`adopted_symbol` uniqueness constraint** — `resolutions.adopted_symbol` has a
  `UNIQUE` constraint but multiple PDFs may reference the same adopted resolution (e.g. in
  explanation-of-vote sessions). Relax to allow `NULL` and non-unique non-null values, or
  use an upsert strategy.

- [ ] **Amendment table population** — `src/db/models.py` defines the `amendments` table
  but `import_json_to_db.py` does not populate it yet. Wire up amendment import when the
  extractor starts producing amendment records.

---

## Testing

- [ ] **Test coverage for session-65 patterns** — Add unit tests for Roman-numeral
  adoption lines, amendment adoption lines, and the "A recorded vote was taken." signal.

- [ ] **Integration test fixture** — Add a golden JSON fixture for each of the five
  sample PDFs so regressions in extraction output are caught automatically.

- [ ] **Validator test for Roman numeral symbols** — Once the validator accepts Roman
  numerals, add a corresponding test.

---

## Documentation

- [ ] **LLM enrichment walkthrough** — Add a section to README.md showing a concrete
  example of running with `--llm` and what fields it populates vs. rule-based extraction.
