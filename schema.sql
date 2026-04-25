-- ─────────────────────────────────────────────────────────────────────────────
-- SecureVault — Supabase Schema
-- Run this in: Supabase Dashboard → SQL Editor → New Query → Run
-- ─────────────────────────────────────────────────────────────────────────────

-- Users table
-- kdf_salt is a random 32-byte value used to derive the AES-256 key via PBKDF2.
-- The raw AES key is NEVER stored here. A full DB leak cannot decrypt any files.
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL    PRIMARY KEY,
    username      TEXT         NOT NULL UNIQUE,
    password_hash TEXT         NOT NULL,
    kdf_salt      BYTEA        NOT NULL,
    created_at    TIMESTAMPTZ  DEFAULT NOW()
);

-- Files table
-- Stores metadata only. The encrypted file blob lives in Supabase Storage.
CREATE TABLE IF NOT EXISTS files (
    id            BIGSERIAL    PRIMARY KEY,
    user_id       BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_name TEXT         NOT NULL,
    stored_name   TEXT         NOT NULL,   -- random hex prefix + filename + .enc
    file_size     INTEGER      NOT NULL,   -- original (pre-encryption) size in bytes
    uploaded_at   TIMESTAMPTZ  DEFAULT NOW()
);

-- Index for fast per-user file lookups
CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id);

-- ─── ROW LEVEL SECURITY (RLS) ─────────────────────────────────────────────────
-- RLS ensures that even if someone calls the Supabase API directly, they can
-- only ever see their own rows. This is a defence-in-depth measure.
-- Our Flask app uses the service_role key (bypasses RLS), but enabling RLS
-- protects against any future client-side API calls using the anon key.

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE files ENABLE ROW LEVEL SECURITY;

-- Since our Flask backend uses the service_role key (full access),
-- we don't need permissive policies for the app itself.
-- These are a safety net for any anon/client access attempts.
CREATE POLICY "No anon access to users" ON users
    FOR ALL USING (false);

CREATE POLICY "No anon access to files" ON files
    FOR ALL USING (false);
