-- Migration: add speakers.organization column and update unique constraint
--
-- Run once against an existing database that was created before this column
-- was added to the ORM model.
--
-- Usage:
--   psql "$DATABASE_URL" -f scripts/migrate_add_speaker_organization.sql

BEGIN;

-- 1. Add the new nullable column
ALTER TABLE speakers
    ADD COLUMN IF NOT EXISTS organization VARCHAR(400);

-- 2. Replace the old two-column unique constraint with a three-column one.
--    The old name was "uq_speaker" (name, country_id).
--    The new constraint is (name, country_id, organization).
--    NULL values in organization are treated as distinct by PostgreSQL's
--    unique constraint, which is the correct behaviour here.
ALTER TABLE speakers
    DROP CONSTRAINT IF EXISTS uq_speaker;

ALTER TABLE speakers
    ADD CONSTRAINT uq_speaker UNIQUE (name, country_id, organization);

COMMIT;
