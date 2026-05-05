# TODO

Open tasks and known limitations for the un-extractor pipeline.

---

## Extraction accuracy

- [ ] **Vision model fallback for worst-quality pages** — For pages where re-OCR quality
  is still low (very poor scan, unusual typefaces), fall back to rendering the page as
  an image and calling Claude Vision to extract text directly.  Claude handles
  two-column layout natively.  Trigger only as a last resort (expensive: ~$0.01/page).

- [ ] **Vision-based failed-vote extraction for pre-1980 documents** — Pre-1980 verbatim
  records often print per-country vote breakdowns in page-bottom footnotes rather than
  inline, and these footnotes frequently span two pages.  `column_boxes()` silently drops
  footnote regions, so rule-based extraction misses them entirely; superscript-to-footnote
  association is also unreliable in PyMuPDF's block structure for scanned documents.
  A vision model sees the layout as a human does (horizontal rule, smaller font, superscript
  reference, list continuation on the next page) and can extract the full country list as
  structured JSON matching the `CountryVote` schema.  Approach: (1) identify meetings
  where a recorded-vote or not-adopted marker was found but no `country_votes` rows were
  extracted, (2) render those pages at ~150 DPI, (3) feed to Claude with a structured
  extraction prompt.  The pre-1980 GA corpus is ~1,000–1,500 PDFs so targeted coverage
  is well under $500 even at $0.01/page.  The earliest documents (1940s–early 1950s)
  recorded many votes only as "adopted by acclamation" with no country breakdown at all —
  vision cannot recover data that was never recorded.  Develop alongside the
  failed-vote regex work (see Database section).

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

- [x] **Incremental processing** — `process_dataset.py` re-processes every PDF on every
  run.  Add a lightweight "already processed" check — a `processed_at` timestamp column
  in the `documents` table, or a persistent set of document symbols in a sidecar file —
  so that re-runs only touch new or changed PDFs.  This is critical once the dataset
  exceeds a few thousand documents.

- [x] **Schema migration framework** — Schema changes are currently applied via ad-hoc
  `ALTER TABLE IF NOT EXISTS` blocks scattered across import scripts.  Migrating to
  **Alembic** would give a versioned migration history, safe rollback, and a single
  canonical view of the schema at any revision.  The existing `src/db/models.py`
  SQLAlchemy models are already Alembic-compatible; the main work is generating the
  initial migration and wiring `alembic upgrade head` into the pipeline entry points.

---

## Database

- [ ] **Failed-vote extraction** — `vote_extractor.py` only matches `"was adopted"`;
  draft resolutions that fail a recorded vote (`"was not adopted"`, `"has not been adopted"`)
  are silently dropped.  Steps: (1) expand `_ADOPTION_RE` to also match the not-adopted
  variants, (2) add an `adopted: bool` field to the `Resolution` Pydantic model and the
  `votes` DB table, (3) set `adopted=False` when the failure branch matches — country-vote
  extraction is unchanged since the In favour/Against/Abstaining block structure is
  identical.  Footnote-based vote records in pre-1980 documents (where the per-country
  breakdown is printed as a page-bottom footnote rather than inline) are a separate, harder
  problem: they require detecting footnote blocks by y-coordinate and font size after
  `column_boxes()` extraction, then matching superscript reference numbers to their labels.

- [ ] **Amendment table population** — `src/db/models.py` defines the `amendments` table
  but `import_json_to_db.py` does not populate it yet. ~40 % of amendment-related stage
  directions have no document symbol (oral amendments, context-dependent references), so
  extraction would silently miss most records. Additionally `resolution_id` is non-nullable,
  making it impossible to store oral/undocumented amendments. Defer until the schema is
  relaxed and the extractor handles contextual resolution references.

- [x] **Full-text search index** — Add a `tsvector` GIN index on `speeches.text` and
  expose a `/search` endpoint in un-project.org.  PostgreSQL FTS handles stopwords,
  stemming, and `ts_rank` scoring natively.  A `to_tsvector('english', text)` trigger
  column on `speeches` is the simplest implementation; a separate `search_vector`
  column with a `BEFORE INSERT OR UPDATE` trigger avoids re-computing on every query.
  — Implemented in un-project.org as a materialized view (`search_index`) with a GIN
  index on a weighted tsvector (speaker A, country B, text C) covering speeches and
  resolutions. Refreshed via `REFRESH MATERIALIZED VIEW CONCURRENTLY` on pg_notify.
  A trigger column on speeches would duplicate this at lower quality with extra write
  overhead on every pipeline INSERT — not needed.

---

## Analytics & enrichment

- [x] **Topic modeling on speeches** — Run BERTopic (or LDA as a lighter baseline) over
  the SC Debates corpus and the General Debate full texts to produce per-speech topic tags
  and per-resolution topic distributions.  Store results in a `speech_topics
  (speech_id, topic_id, weight)` table.  Topics surface naturally on country and
  resolution profile pages as "most discussed themes".

- [x] **Country network centrality** — Build a per-year co-sponsorship graph and compute
  PageRank and betweenness-centrality scores to rank the most influential resolution
  sponsors.  Store in a `country_network_stats (country_id, year, pagerank,
  betweenness)` table alongside the ideal points.  The `resolution_sponsors` table
  already has all the edges needed.

- [ ] **`speech_vote_links` bridge table** — Materialize the speech→vote pairing that is
  currently only expressible as a multi-condition join (`item_id` + `position_in_item` +
  `country_id`).  Schema:
  `speech_vote_links (speech_id, vote_id, country_id, link_type)` where `link_type` is
  one of `pre_vote` (speech precedes the vote in the same item), `explanation_of_vote`
  (speech follows the vote), or `mention` (speech explicitly names the resolution symbol
  via `speech_resolution_mentions`).  Populate with a script analogous to
  `tag_speech_types.py`; re-run after any new import.  Enables direct joining of speech
  text / sentiment with `country_votes.vote_position` without reconstructing meeting flow
  each time.  Coverage is limited to GA/SC verbatim records (extracted PDFs); the SC
  Debates corpus and GA General Debate speeches connect to votes only via `mention` links.

- [ ] **Text-augmented issue-specific ideal points** — Standard IRT ideal points are
  estimated from final-passage votes across all issues; per-issue subsets (Palestine,
  nuclear, human rights, etc.) typically yield too few votes for reliable country
  separation, especially within blocs that vote uniformly.  The primary text source is
  **General Debate and pre-vote substantive debate speeches**: both are unconstrained by
  vote outcomes and show real positional variation within blocs.  Explanation-of-vote
  speeches are downstream of a committed vote and do not add within-bloc differentiation
  (a "reluctant yes" and an "enthusiastic yes" are identical IRT inputs); the narrow
  exception is abstentions, where speech text can clarify which side of the midpoint a
  country leans toward.  Within the ~130 countries voting yes on Palestine resolutions,
  their September General Debate speeches vary substantially in emphasis, specific demands,
  and floor time — that is real positional signal.  Proposed approach: (1) for each
  Voeten issue cluster (`issue_me`, `issue_nu`, `issue_co`, `issue_hr`, `issue_ec`,
  `issue_di`), use vote outcomes as anchor labels; (2) embed General Debate and pre-vote
  debate speeches (Claude embeddings or direct API scoring) and regress onto vote labels
  to produce continuous position scores, calibrated within-session to handle
  context-dependent language; (3) apply to sessions and countries with no or few votes on
  the issue.  Validation challenge: within-sample fit against vote labels is circular;
  external validators to consider include bilateral voting alignment in other forums, arms
  transfers, diplomatic recognition, or whether text-derived scores predict future votes
  better than past votes alone.

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
