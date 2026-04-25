#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Full pipeline: extract PDFs → rebuild local database from scratch.
# Run from the repo root.
# ---------------------------------------------------------------------------

export DATABASE_URL="postgresql://myuser:mypassword@localhost:5433/unproject"

# ---------------------------------------------------------------------------
# 0. Extract text from PDFs
# ---------------------------------------------------------------------------

# Process all PDFs (adjust --workers to your CPU count).
# --use-ods fetches cleaner HTML from undocs.org when available (needs network).
# --no-reocr disables Tesseract fallback if ocrmypdf is not installed.
python process_dataset.py data/raw_pdfs/ --output output/ --workers 8 --use-ods

# SC PDFs via CR-UNSC (only needed if not already downloaded):
#python scripts/import_crUnsc_pdfs.py
#python process_dataset.py data/raw_pdfs/en/sc/ --output output/ --workers 8 --use-ods

# ---------------------------------------------------------------------------
# 1. Drop and recreate the database
# ---------------------------------------------------------------------------

docker exec -i un-projectorg-db-1 psql -U myuser -d postgres -c "DROP DATABASE IF EXISTS unproject;" \
  && docker exec -i un-projectorg-db-1 psql -U myuser -d postgres -c "CREATE DATABASE unproject;"

# ---------------------------------------------------------------------------
# 2. Import extracted JSONs (creates schema automatically)
# ---------------------------------------------------------------------------

python import_json_to_db.py output/ --recreate

# ---------------------------------------------------------------------------
# 3. Import authoritative UNDL voting data (applies schema migrations)
# ---------------------------------------------------------------------------

python scripts/import_undl_votes.py --db $DATABASE_URL

# Backfill GA vote tally counts (yes/no/abstain totals) from Voeten dataset
python scripts/import_harvard_ga_votes.py --db $DATABASE_URL

# Merge duplicate country rows created by the two import passes above
python scripts/fix_country_duplicates.py --db $DATABASE_URL

# ---------------------------------------------------------------------------
# 4. Enrich resolutions with Voeten metadata and SC veto data
# ---------------------------------------------------------------------------

# importantvote flag + issue-area codes
python scripts/import_voeten_resolution_meta.py --db $DATABASE_URL

# SC veto data 1946–present (DPPA-SCVETOES, HDX)
python scripts/import_sc_vetoes.py --db $DATABASE_URL

# ---------------------------------------------------------------------------
# 5. Import SC Debates corpus (Schönfeld et al., ~452 MB)
# ---------------------------------------------------------------------------

python scripts/import_sc_debates.py --db $DATABASE_URL

# ---------------------------------------------------------------------------
# 6. Import supplementary DHL datasets
# ---------------------------------------------------------------------------

python scripts/import_undl_member_states.py --db $DATABASE_URL
python scripts/import_undl_ga_resolutions.py --db $DATABASE_URL
python scripts/import_undl_representatives.py --db $DATABASE_URL

# ---------------------------------------------------------------------------
# 7. Import General Debate metadata and full-text corpus
# ---------------------------------------------------------------------------

python scripts/import_undl_general_debate.py --db $DATABASE_URL
python scripts/import_gdebate_corpus.py --db $DATABASE_URL

# ---------------------------------------------------------------------------
# 8. Import resolution full texts and citation network
# ---------------------------------------------------------------------------

python scripts/import_ga_resolution_texts.py --db $DATABASE_URL

python scripts/import_crUnsc_texts.py --db $DATABASE_URL
python scripts/import_crUnsc_citations.py --db $DATABASE_URL

# SC draft texts + co-sponsorship data (UNBench, MIT)
python scripts/import_unbench_sc_drafts.py --data-dir ./UNBench-all/ --db $DATABASE_URL

# ---------------------------------------------------------------------------
# 9. Speech-level enrichment (run after all resolution imports are complete)
# ---------------------------------------------------------------------------

# Tag speeches as substantive / explanation_of_vote / procedural
python scripts/tag_speech_types.py --db $DATABASE_URL

# Extract co-sponsorship mentions from speech text → resolution_sponsors
# (GA all periods + SC pre-1994; post-1994 SC covered by import_unbench_sc_drafts above)
python scripts/extract_speech_cosponsors.py --db $DATABASE_URL

# Extract resolution symbol mentions from speech text → speech_resolution_mentions
python scripts/extract_speech_resolution_mentions.py --db $DATABASE_URL

# ---------------------------------------------------------------------------
# 10. Compute derived analytics
# ---------------------------------------------------------------------------

# Pairwise country voting-alignment time series
python scripts/compute_alignment_series.py --db $DATABASE_URL

# Ideal points — full dynamic Bayesian IRT (BSV 2017 ordinal-probit Gibbs sampler)
# Produces source='bsv2017_mcmc' rows matching Voeten's published scale.
# Takes several hours; reduce --n-iter for a quick test run.
python scripts/compute_ideal_points_mcmc.py --n-iter 10000 --n-burn 2000 --thin 20 --db $DATABASE_URL

# Cross-sectional IRT extension for sessions beyond the MCMC dataset cutoff:
python scripts/import_voeten_ideal_points.py --db $DATABASE_URL
python scripts/compute_ideal_points.py --extend --db $DATABASE_URL

# ---------------------------------------------------------------------------
# 11. un-project.org website sync (run from the un-project.org repo)
# ---------------------------------------------------------------------------

# DB_HOST=localhost DB_PORT=5433 python scripts/populate_iso_and_flags.py
# docker compose exec web python manage.py refresh_search_index --full
