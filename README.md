# davidlong.tech — Backend API

Flask API backend for davidlong.tech and Research Studio.

- **Frontend**: davidlong.tech (Next.js on Vercel)
- **Backend**: This repo (Flask on Heroku)
- **Database**: Heroku Postgres

## Local development

### Database setup (one-time)

1. Create the `davidlong_tech` database (run as postgres superuser):

```bash
psql -U postgres -d postgres -f scripts/create_database.sql
# Or: sudo -u postgres psql -d postgres -f scripts/create_database.sql
```

2. If `dev_user` lacks schema permissions, grant them:

```bash
psql -U postgres -d davidlong_tech -c "GRANT ALL ON SCHEMA public TO dev_user; GRANT CREATE ON SCHEMA public TO dev_user;"
```

3. Run migrations:

```bash
PGPASSWORD=dev123 psql -d davidlong_tech -U dev_user -h localhost -f migrations/001_add_user_table.sql
PGPASSWORD=dev123 psql -d davidlong_tech -U dev_user -h localhost -f migrations/002_add_password_reset_table.sql
PGPASSWORD=dev123 psql -d davidlong_tech -U dev_user -h localhost -f migrations/003_add_research_studio_schema.sql
PGPASSWORD=dev123 psql -d davidlong_tech -U dev_user -h localhost -f migrations/004_seed_research_studio.sql
```

### Running the backend

All commands run inside the project's virtual environment (`venv`).

```bash
# Option A: Use the run script (creates venv if needed, installs deps, starts Flask)
./run.sh

# Option B: Manual
python3 -m venv venv
source venv/bin/activate   # or venv\Scripts\activate on Windows
pip install -r requirements.txt

# Set environment (or use .env)
export DATABASE_URL="postgresql://dev_user:dev123@localhost:5432/davidlong_tech?sslmode=disable"
export JWT_SECRET="dev-secret-change-in-production"

# Run
flask run --port 5000
# or: gunicorn app:app
```

## API

- `GET /api/health` — Health check
- Auth routes (TBD): `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`

## Deploy to Heroku

```bash
git push heroku main
```
