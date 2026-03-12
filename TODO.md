# TODO

Open tasks and known limitations for the un-extractor pipeline.

---

## Extraction accuracy

- [ ] **`unknown` draft symbol (remaining)** — A handful of adoption lines ("The draft
  decision was adopted.") appear with no preceding bold header and no parenthetical symbol,
  so the draft symbol cannot be resolved. These are typically procedural decisions that
  don't correspond to a numbered draft. Consider skipping resolution creation for these
  cases rather than storing `draft_symbol = "unknown"`.

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

- [ ] **Amendment table population** — `src/db/models.py` defines the `amendments` table
  but `import_json_to_db.py` does not populate it yet. Wire up amendment import when the
  extractor starts producing amendment records.

---

## Documentation

- [ ] **LLM enrichment walkthrough** — Add a section to README.md showing a concrete
  example of running with `--llm` and what fields it populates vs. rule-based extraction.
