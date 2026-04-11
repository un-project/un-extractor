# TODO

Open tasks and known limitations for the un-extractor pipeline.

---

## Extraction accuracy

- [x] **Scanned-document country vote lists** — Older OCR documents (1970s–1980s) sometimes
  have country names in vote lists split across lines with hyphen-space breaks (e.g.
  `"Ar- gentina"`). The hyphen-space collapse in `normalize_country_name` handles most cases,
  but multi-word names split mid-word (e.g. `"United King- dom"`) may still fail. Audit the
  oldest sessions after a full pipeline rerun.

- [x] **OCR quality detector** — Add a heuristic score (ratio of alpha tokens that look
  like real words) to classify whether the embedded text layer in a PDF is usable.
  A score below ~0.4 signals a stale/garbage OCR layer and should trigger re-OCR.
  Gate the re-OCR fallback (see below) on this score so it only runs where needed.

- [x] **Re-OCR with `ocrmypdf` / Tesseract 5** — For PDFs whose quality score is low,
  bypass the embedded text layer entirely: render each page to a 300 DPI image and
  re-OCR with `ocrmypdf` (which runs Tesseract 5 + deskew + denoising automatically).
  `ocrmypdf` can be invoked as a subprocess and produces a new PDF with a clean text
  layer that feeds the existing PyMuPDF pipeline unchanged.  This is expected to
  recover most pre-1990 GA and SC sessions.

- [ ] **Vision model fallback for worst-quality pages** — For pages where re-OCR quality
  is still low (very poor scan, unusual typefaces), fall back to rendering the page as
  an image and calling Claude Vision to extract text directly.  Claude handles
  two-column layout natively.  Trigger only as a last resort (expensive: ~$0.01/page).

- [x] **Image pre-processing before OCR** — Run `opencv` deskew, adaptive binarization
  (`cv2.adaptiveThreshold`), and denoising (`cv2.fastNlMeansDenoising`) on page images
  before Tesseract to handle uneven illumination, scanner speckle, and rotated scans.
  Also strip punch-hole shadows and margin borders that confuse column detection.

- [x] **ALL-CAPS speaker attribution patterns** — Pre-1985 documents print attributions
  as `MR. MOLOTOV (Union of Soviet Socialist Republics):`.  The current `_SPEAKER_RE`
  and `_TITULAR_RE` patterns in `src/structure/detect_sections.py` require mixed-case
  titles (`Mr.`, `The President`).  Add uppercase-aware variants or make the patterns
  case-insensitive to recover speaker turns in early GA/SC sessions.

- [x] **Single-column layout detection** — `src/pdf/extract_text.py` hardcodes a
  midpoint split assuming two columns.  Very early GA meetings (sessions 1–10, late
  1940s) used single-column layouts; the split creates two half-empty pseudo-columns
  and scrambles reading order.  If fewer than ~20 % of blocks have x0 > midpoint,
  treat the page as single-column and skip the split.

- [x] **Hyphenation repair across column and page breaks** — Pre-1990 documents typeset
  running text with end-of-line hyphenation; column and page breaks split words
  mid-hyphen (e.g. `"recom-\nmendation"`).  A post-OCR pass joining `word-\ncontinuation`
  tokens (with a dictionary check) would clean up many malformed tokens and improve
  downstream regex matching.

- [x] **UN ODS HTML as alternative text source** — The UN Official Document System
  (`documents.un.org`) sometimes has an HTML or Word-derived rendition of the same
  verbatim record that is cleaner than the scanned PDF.  A script could fetch the
  HTML version using the document symbol as the lookup key, score its quality against
  the PDF-extracted text, and prefer whichever source is better.

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

---

## Voting analytics & geopolitics

The UNDL voting CSVs (already imported: ~947k GA rows, ~41k SC rows) provide
a complete `(country, resolution, vote_position, date)` record from 1946–2026
that is sufficient for the following analytical features.

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
