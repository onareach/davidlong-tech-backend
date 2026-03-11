-- Migration: Add is_fallback to prompts, research_prompt_id to entries
-- Run: PGPASSWORD=dev123 psql -d davidlong_tech -U dev_user -h localhost -f migrations/005_prompts_and_entries_schema.sql
-- Heroku: heroku run "psql \$DATABASE_URL -f migrations/005_prompts_and_entries_schema.sql" -a davidlong-tech-backend

-- Add is_fallback to tbl_research_prompts (flags prompts used when no continuity prompts exist)
ALTER TABLE tbl_research_prompts
ADD COLUMN IF NOT EXISTS is_fallback BOOLEAN NOT NULL DEFAULT FALSE;

-- Add research_prompt_id to tbl_research_entries (links entry to the prompt that inspired it)
ALTER TABLE tbl_research_entries
ADD COLUMN IF NOT EXISTS research_prompt_id BIGINT REFERENCES tbl_research_prompts(research_prompt_id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_tbl_research_entries_prompt_id
ON tbl_research_entries (research_prompt_id);
