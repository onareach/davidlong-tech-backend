-- Migration: account activation state for login privilege
-- Run: PGPASSWORD=dev123 psql -d davidlong_tech -U dev_user -h localhost -f migrations/009_add_user_is_active.sql

ALTER TABLE tbl_user
  ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;

CREATE INDEX IF NOT EXISTS idx_tbl_user_is_active ON tbl_user(is_active);

COMMENT ON COLUMN tbl_user.is_active IS 'When false, account cannot authenticate and active sessions are treated as unauthenticated.';
