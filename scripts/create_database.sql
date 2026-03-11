-- Create davidlong_tech database and grant dev_user access.
-- Run as postgres superuser, e.g.:
--   psql -U postgres -d postgres -f scripts/create_database.sql
--   sudo -u postgres psql -d postgres -f scripts/create_database.sql

CREATE DATABASE davidlong_tech;
GRANT ALL PRIVILEGES ON DATABASE davidlong_tech TO dev_user;

-- Connect and grant schema permissions (dev_user needs CREATE on public)
\c davidlong_tech
GRANT ALL ON SCHEMA public TO dev_user;
GRANT CREATE ON SCHEMA public TO dev_user;
