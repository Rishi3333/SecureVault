# SecureVault

## Setup — Step by Step

### Step 1 — Create a Supabase account

Go to https://supabase.com and sign up with GitHub. No credit card required.

### Step 2 — Create a new project

- Click **New Project**
- Choose a name (e.g. `securevault`)
- Choose a region close to you
- Set a strong database password — **save this somewhere safe**
- Click **Create new project** and wait ~2 minutes for it to provision

### Step 3 — Set up the database tables

- In the Supabase dashboard, go to **SQL Editor** → **New Query**
- Paste the entire contents of `schema.sql`
- Click **Run**
- You should see "Success. No rows returned."

### Step 4 — Create the storage bucket

- Go to **Storage** in the left sidebar
- Click **New bucket**
- Name it exactly: `encrypted-files`
- Set it to **Private** (not public — files should never be directly accessible)
- Click **Create bucket**

### Step 5 — Get your credentials

You need three values from the Supabase dashboard:

**SUPABASE_URL and SUPABASE_KEY:**
- Go to **Project Settings** → **API**
- Copy the **Project URL** → this is your `SUPABASE_URL`
- Under **Project API keys**, copy the **service_role** key (not the anon key)
  → this is your `SUPABASE_KEY`
- ⚠️ The service_role key has full DB access. Never expose it in frontend code.

**DATABASE_URL:**
- Go to **Project Settings** → **Database**
- Scroll to **Connection string** → select the **URI** tab
- Copy the string — it looks like:
  `postgresql://postgres:[YOUR-PASSWORD]@db.xxxx.supabase.co:5432/postgres`
- Replace `[YOUR-PASSWORD]` with the database password you set in Step 2

### Step 6 — Configure your .env file

```bash
cp .env.example .env
```

Open `.env` and fill in the three values from Step 5, plus a Flask secret key:

```
FLASK_SECRET_KEY=   # run: python -c "import secrets; print(secrets.token_hex(32))"
SUPABASE_URL=       # https://your-project-ref.supabase.co
SUPABASE_KEY=       # your service_role key
DATABASE_URL=       # postgresql://postgres:password@db.ref.supabase.co:5432/postgres
```

### Step 7 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 8 — Run the app

```bash
python app.py
```

Open http://127.0.0.1:5000 in your browser.

---

## How to verify it's working

After registering and uploading a file:

1. **Check Supabase Storage** — go to Storage → encrypted-files bucket.
   You should see a `.enc` file with a random hex prefix.

2. **Check Supabase Database** — go to Table Editor → files table.
   You should see a row with the original filename, stored name, and file size.
   Crucially, there is no encryption key column — the key is never stored.

3. **Check the users table** — you'll see `password_hash` (bcrypt) and `kdf_salt`
   (random bytes). No AES key. A full database dump still cannot decrypt any files.

---

## Project Structure

```
securevault-supabase/
├── app.py              # Flask app — Supabase Storage + PostgreSQL
├── schema.sql          # Run once in Supabase SQL Editor
├── requirements.txt    # pip dependencies
├── .env.example        # Template for your credentials — copy to .env
├── .gitignore          # Prevents .env and __pycache__ being committed
└── templates/
    ├── base.html
    ├── login.html
    ├── register.html
    └── dashboard.html
```

---

## Key implementation notes

**Why `service_role` key and not `anon` key?**
The anon key is for client-side (browser) access and is subject to Row Level
Security (RLS) policies. Our Flask backend is server-side and needs full read/write
access to the database and storage bucket, so it uses the service_role key.
This key must never be exposed in frontend code or public repositories.

**Why psycopg2 instead of the Supabase Python client for DB?**
The Supabase Python client's database interface works via the PostgREST REST API,
which has some limitations with binary data (BYTEA columns for kdf_salt).
psycopg2 connects directly to PostgreSQL and handles binary data natively,
making it a more reliable choice for this use case.

**Storage upload atomicity**
If the Supabase Storage upload succeeds but the PostgreSQL INSERT fails, the
orphaned `.enc` file is automatically deleted from the bucket. This prevents
accumulation of unreferenced encrypted blobs.

**Deploying to production**
For production deployment (e.g. Render, Railway, Fly.io — all free tier):
- Set the three environment variables in the platform's dashboard
- Set `debug=False` in `app.run()`
- Use gunicorn: `gunicorn app:app`
- Add `gunicorn` to requirements.txt
