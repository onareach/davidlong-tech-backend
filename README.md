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
PGPASSWORD=dev123 psql -d davidlong_tech -U dev_user -h localhost -f migrations/005_prompts_and_entries_schema.sql
PGPASSWORD=dev123 psql -d davidlong_tech -U dev_user -h localhost -f migrations/006_seed_fallback_prompts.sql
PGPASSWORD=dev123 psql -d davidlong_tech -U dev_user -h localhost -f migrations/007_add_user_is_admin.sql
PGPASSWORD=dev123 psql -d davidlong_tech -U dev_user -h localhost -f migrations/008_branches_mysteries_user_id.sql
PGPASSWORD=dev123 psql -d davidlong_tech -U dev_user -h localhost -f migrations/009_add_user_is_active.sql
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
# Optional: for AI "Edit for clarity" (light edit)
export OPENAI_API_KEY="sk-..."
export OPENAI_EDIT_MODEL="gpt-4o-mini"   # default
# Password reset emails (optional): SendGrid + public site URL
export FRONTEND_URL="http://localhost:3000"
# export SENDGRID_API_KEY="..."
# export RESET_EMAIL_FROM="you@yourdomain.com"

# Run
flask run --port 5000
# or: gunicorn app:app
```

## API

- `GET /api/health` — Health check
- `POST /api/auth/register` — Body: `{ email, password, display_name? }`
- `POST /api/auth/login` — Body: `{ email, password }`; returns `{ user, token }`
- `POST /api/auth/logout` — Clears auth cookie
- `GET /api/auth/me` — Returns `{ user }` or `{ user: null }`; user includes `is_admin`
- `PATCH /api/auth/me` — Body: optional `email`, `display_name`, `new_password` + `current_password`
- `POST /api/auth/forgot-password` — Body: `{ email }` (generic success; no enumeration)
- `POST /api/auth/reset-password` — Body: `{ token, new_password }`
- `GET /api/admin/users` — List users (admin only)
- `PATCH /api/admin/users/<id>` — Body: `{ is_admin: boolean }` (admin only)
- `PATCH /api/admin/users/<id>/activation` — Body: `{ is_active: boolean }` (admin only; admin accounts cannot be inactivated)

Branches and mysteries: catalog rows have `user_id` null; user-created rows are scoped per user (`GET` lists catalog + own).

## Deploy to Heroku

```bash
git push heroku main
```

### AI light edit (optional)

The "Edit for clarity" feature calls OpenAI from the backend. On Heroku, set:

- **OPENAI_API_KEY** (required if you use the feature): your OpenAI API key (Settings → Config Vars).
- **OPENAI_EDIT_MODEL** (optional): default `gpt-4o-mini`. Set to `gpt-4o` for higher quality.

If `OPENAI_API_KEY` is not set, the endpoint returns 503 and the frontend shows an error.
