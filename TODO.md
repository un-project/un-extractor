# TODO

Open tasks and known limitations for the un-extractor pipeline.

---

## Extraction accuracy

- [ ] **Vision model fallback for worst-quality pages** — For pages where re-OCR quality
  is still low (very poor scan, unusual typefaces), fall back to rendering the page as
  an image and calling Claude Vision to extract text directly.  Claude handles
  two-column layout natively.  Trigger only as a last resort (expensive: ~$0.01/page).

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

---

## Documentation

- [ ] **LLM enrichment walkthrough** — Add a section to README.md showing a concrete
  example of running with `--llm` and what fields it populates vs. rule-based extraction.
