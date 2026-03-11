-- Grant dev_user permission to create tables in public schema.
-- Run as postgres superuser, e.g.:
--   psql -U postgres -d davidlong_tech -f scripts/grant_schema_permissions.sql

\c davidlong_tech

GRANT ALL ON SCHEMA public TO dev_user;
GRANT CREATE ON SCHEMA public TO dev_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO dev_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO dev_user;
