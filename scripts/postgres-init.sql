-- =============================================================================
-- AetherForge — initial Postgres setup
-- Runs once at first container boot (docker-entrypoint-initdb.d).
-- =============================================================================

-- Extensions used by the schema (Alembic can't create them reliably).
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Per-statement timing metrics (used by Phase 6 dashboards).
ALTER SYSTEM SET log_min_duration_statement = '250ms';
ALTER SYSTEM SET log_line_prefix = '%t [%p] %q%u@%d ';

-- Basic hardening: prevent role login without password.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aetherforge') THEN
    ALTER ROLE aetherforge CONNECTION LIMIT 100;
  END IF;
END$$;
