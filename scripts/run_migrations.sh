#!/usr/bin/env bash
# Run all migrations against davidlong_tech.
# Requires: database exists, dev_user has CREATE on public schema.

set -e
cd "$(dirname "$0")/.."

DB="${DATABASE_NAME:-davidlong_tech}"
USER="${DB_USER:-dev_user}"
HOST="${DB_HOST:-localhost}"

export PGPASSWORD="${PGPASSWORD:-dev123}"

for f in migrations/001_add_user_table.sql \
         migrations/002_add_password_reset_table.sql \
         migrations/003_add_research_studio_schema.sql \
         migrations/004_seed_research_studio.sql; do
  echo "Running $f..."
  psql -d "$DB" -U "$USER" -h "$HOST" -f "$f"
done

echo "Migrations complete."
