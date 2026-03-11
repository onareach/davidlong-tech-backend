#!/usr/bin/env bash
# Create davidlong_tech database for local development.
# Requires postgres superuser for database creation (dev_user lacks CREATEDB).
# After this, dev_user can connect and run migrations.

set -e
cd "$(dirname "$0")/.."

DB_NAME="davidlong_tech"

# Try createdb as current user (often works if you're postgres or have CREATEDB)
if createdb -h localhost "$DB_NAME" 2>/dev/null; then
  echo "Created database $DB_NAME"
  exit 0
fi

# Try with postgres user
if PGPASSWORD="${PGPASSWORD}" createdb -U postgres -h localhost "$DB_NAME" 2>/dev/null; then
  echo "Created database $DB_NAME as postgres"
  exit 0
fi

# Run the SQL script (requires postgres superuser; may prompt for password)
echo "Attempting via SQL script (may prompt for postgres password)..."
if psql -U postgres -h localhost -d postgres -f scripts/create_database.sql; then
  echo "Created database $DB_NAME via SQL script"
  exit 0
fi

echo ""
echo "Could not create database. Run manually as postgres superuser:"
echo "  psql -U postgres -d postgres -f scripts/create_database.sql"
echo "Or:"
echo "  sudo -u postgres psql -d postgres -f scripts/create_database.sql"
exit 1
