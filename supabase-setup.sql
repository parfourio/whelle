-- Whelle Supabase Setup
-- Run this in your Supabase SQL Editor

-- PROVIDERS table
create table providers (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  password_hash text not null,
  name text default '',
  bio text default '',
  photo_url text default '',
  modality text default '',
  location text default '',
  services jsonb default '[]',
  slug text unique not null,
  active boolean default true,
  approved boolean default false,
  created_at timestamptz default now()
);

-- MEMBERS table
create table members (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  password_hash text not null,
  name text default '',
  photo_url text default '',
  location text default '',
  active boolean default true,
  created_at timestamptz default now()
);

-- Disable RLS (we use service key from server, not client-side auth)
alter table providers disable row level security;
alter table members disable row level security;
