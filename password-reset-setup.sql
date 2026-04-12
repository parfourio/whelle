-- Run this in your Supabase SQL editor (Whelle project)
-- Creates the password_reset_tokens table used by the forgot-password flow

create table if not exists password_reset_tokens (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  token text unique not null,
  user_type text not null,  -- 'provider' or 'member'
  expires_at timestamptz not null,
  created_at timestamptz default now()
);

-- Disable RLS (same pattern as providers/members tables)
alter table password_reset_tokens disable row level security;

-- Index for fast token lookups
create index if not exists idx_reset_tokens_token on password_reset_tokens(token);
create index if not exists idx_reset_tokens_email on password_reset_tokens(email);
