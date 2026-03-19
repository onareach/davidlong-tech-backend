-- Migration: Per-user branches and mysteries (NULL user_id = shared catalog)
-- Run: PGPASSWORD=dev123 psql -d davidlong_tech -U dev_user -h localhost -f migrations/008_branches_mysteries_user_id.sql

ALTER TABLE tbl_research_branches
  ADD COLUMN IF NOT EXISTS user_id INTEGER NULL
    REFERENCES tbl_user(user_id) ON DELETE CASCADE;

ALTER TABLE tbl_research_mysteries
  ADD COLUMN IF NOT EXISTS user_id INTEGER NULL
    REFERENCES tbl_user(user_id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_tbl_research_branches_user_id ON tbl_research_branches(user_id);
CREATE INDEX IF NOT EXISTS idx_tbl_research_mysteries_user_id ON tbl_research_mysteries(user_id);

COMMENT ON COLUMN tbl_research_branches.user_id IS 'NULL = catalog/seed row visible to all; set = owned by that user only.';
COMMENT ON COLUMN tbl_research_mysteries.user_id IS 'NULL = catalog/seed row visible to all; set = owned by that user only.';
