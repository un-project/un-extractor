# TODO

Open tasks and known limitations for the un-extractor pipeline.

---

## Extraction accuracy

- [ ] **Vision model fallback for worst-quality pages** — For pages where re-OCR quality
  is still low (very poor scan, unusual typefaces), fall back to rendering the page as
  an image and calling Claude Vision to extract text directly.  Claude handles
  two-column layout natively.  Trigger only as a last resort (expensive: ~$0.01/page).

- [ ] **Multi-language PDF support** — The UN publishes verbatim records in all six
  official languages (AR, ZH, EN, FR, RU, ES).  Processing non-English PDFs would
  multiply coverage roughly 6×.  Requires language-aware speaker attribution patterns
  (e.g. `M./Mme` in French, `г-н/г-жа` in Russian), a `language` column on `speeches`,
  and a strategy for linking the same speech across language versions via the shared
  document symbol and speaker position.

- [ ] **GA committee meeting records** — The pipeline targets GA and SC plenary meetings
  (`/PV.`).  Committee verbatim records (`A/C.3/76/SR.N`, `A/AC.109/PV.N`) follow the
  same PDF layout and contain rich debate text on draft resolutions before they reach the
  plenary.  Extending `src/structure/detect_sections.py` to recognise committee summary
  record (SR) headers would capture this content.

---

## Pipeline robustness

- [ ] **Retry on LLM failure** — The LLM enrichment phase catches all exceptions and logs
  a warning, but does not retry. Add a simple exponential backoff (1–2 retries) for
  transient API errors.

- [ ] **Incremental processing** — `process_dataset.py` re-processes every PDF on every
  run.  Add a lightweight "already processed" check — a `processed_at` timestamp column
  in the `documents` table, or a persistent set of document symbols in a sidecar file —
  so that re-runs only touch new or changed PDFs.  This is critical once the dataset
  exceeds a few thousand documents.

- [ ] **Schema migration framework** — Schema changes are currently applied via ad-hoc
  `ALTER TABLE IF NOT EXISTS` blocks scattered across import scripts.  Migrating to
  **Alembic** would give a versioned migration history, safe rollback, and a single
  canonical view of the schema at any revision.  The existing `src/db/models.py`
  SQLAlchemy models are already Alembic-compatible; the main work is generating the
  initial migration and wiring `alembic upgrade head` into the pipeline entry points.

---

## Database

- [ ] **Amendment table population** — `src/db/models.py` defines the `amendments` table
  but `import_json_to_db.py` does not populate it yet. ~40 % of amendment-related stage
  directions have no document symbol (oral amendments, context-dependent references), so
  extraction would silently miss most records. Additionally `resolution_id` is non-nullable,
  making it impossible to store oral/undocumented amendments. Defer until the schema is
  relaxed and the extractor handles contextual resolution references.

- [ ] **Full-text search index** — Add a `tsvector` GIN index on `speeches.text` and
  expose a `/search` endpoint in un-project.org.  PostgreSQL FTS handles stopwords,
  stemming, and `ts_rank` scoring natively.  A `to_tsvector('english', text)` trigger
  column on `speeches` is the simplest implementation; a separate `search_vector`
  column with a `BEFORE INSERT OR UPDATE` trigger avoids re-computing on every query.

---

## Analytics & enrichment

- [ ] **Topic modeling on speeches** — Run BERTopic (or LDA as a lighter baseline) over
  the SC Debates corpus and the General Debate full texts to produce per-speech topic tags
  and per-resolution topic distributions.  Store results in a `speech_topics
  (speech_id, topic_id, weight)` table.  Topics surface naturally on country and
  resolution profile pages as "most discussed themes".

- [ ] **Country network centrality** — Build a per-year co-sponsorship graph and compute
  PageRank and betweenness-centrality scores to rank the most influential resolution
  sponsors.  Store in a `country_network_stats (country_id, year, pagerank,
  betweenness)` table alongside the ideal points.  The `resolution_sponsors` table
  already has all the edges needed.

- [ ] **Resolution passage predictor** — Extend `compute_vote_predictions.py` to output
  a resolution-level forecast: probability of adoption, expected yes/no/abstain shares,
  and expected margin.  Features: sponsor-bloc composition, subject-area flags,
  important-vote indicator, session year, median ideal point of co-sponsors.  Useful for
  un-project.org resolution pages before the vote record is available.

---

## Testing

- [ ] **Property-based tests for `normalize_country_name`** — Use **Hypothesis** to fuzz
  the alias table with random OCR artifacts (random capitalisation, extra whitespace,
  character substitutions, hyphen-space breaks) and assert that the output is always
  either a canonical name or the original string unchanged.  This would catch regressions
  in the alias table that unit tests with fixed examples miss.

- [ ] **Extraction accuracy benchmark** — Build a small gold-standard dataset (e.g. 20
  manually annotated PDFs spanning 1946–2026) and add a `scripts/eval_extraction.py`
  script that computes precision/recall for speaker turns, vote counts, and resolution
  symbols.  Run as part of CI on the existing sample PDFs using the golden fixtures in
  `tests/fixtures/`.

---

## Documentation

- [ ] **LLM enrichment walkthrough** — Add a section to README.md showing a concrete
  example of running with `--llm` and what fields it populates vs. rule-based extraction.
