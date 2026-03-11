-- Migration: Seed fallback prompts into tbl_research_prompts
-- Run: PGPASSWORD=dev123 psql -d davidlong_tech -U dev_user -h localhost -f migrations/006_seed_fallback_prompts.sql
-- Heroku: heroku run "psql \$DATABASE_URL -f migrations/006_seed_fallback_prompts.sql" -a davidlong-tech-backend

-- Idempotent: only insert if no fallback prompts exist
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM tbl_research_prompts WHERE is_fallback = true LIMIT 1) THEN
    INSERT INTO tbl_research_prompts (research_prompt_text, research_prompt_type, is_fallback)
    VALUES
      ('What mystery feels most alive today?', 'fallback', true),
      ('What idea has become clearer recently?', 'fallback', true),
      ('What pattern are you noticing?', 'fallback', true),
      ('What insight would help someone else most?', 'fallback', true);
  END IF;
END $$;
