-- Migration: is_admin on tbl_user + initial admin for onareach@yahoo.com
-- Run: PGPASSWORD=dev123 psql -d davidlong_tech -U dev_user -h localhost -f migrations/007_add_user_is_admin.sql
-- Heroku: heroku pg:psql -a <app> < migrations/007_add_user_is_admin.sql

ALTER TABLE tbl_user
  ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_tbl_user_is_admin ON tbl_user(is_admin);

-- Primary site admin (must exist in tbl_user)
UPDATE tbl_user
SET is_admin = TRUE
WHERE lower(trim(email)) = lower(trim('onareach@yahoo.com'));

COMMENT ON COLUMN tbl_user.is_admin IS 'When true, user may access /api/admin/* and studio admin UI.';
