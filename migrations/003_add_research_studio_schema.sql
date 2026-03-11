-- Migration: Research Studio schema (branches, mysteries, entries, prompts, AI operations)
-- Run: PGPASSWORD=dev123 psql -d davidlong_tech -U dev_user -h localhost -f migrations/003_add_research_studio_schema.sql

-- ============================================
-- 1. BRANCHES
-- ============================================

CREATE TABLE tbl_research_branches (
    research_branch_id BIGSERIAL PRIMARY KEY,
    research_branch_handle TEXT NOT NULL UNIQUE,
    research_branch_name TEXT NOT NULL,
    research_branch_description TEXT,
    research_branches_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- 2. MYSTERIES
-- ============================================

CREATE TABLE tbl_research_mysteries (
    research_mystery_id BIGSERIAL PRIMARY KEY,
    research_mystery_handle TEXT NOT NULL UNIQUE,
    research_mystery_question TEXT NOT NULL,
    research_mystery_description TEXT,
    research_mystery_current_working_answer TEXT,
    research_mystery_audience_relevance TEXT,
    research_mysteries_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- 3. RESEARCH ENTRIES
-- ============================================

CREATE TABLE tbl_research_entries (
    research_entry_id BIGSERIAL PRIMARY KEY,

    user_id BIGINT
        REFERENCES tbl_user(user_id)
        ON DELETE CASCADE,

    research_entry_title TEXT,
    research_entry_raw_text TEXT NOT NULL,
    research_entry_edited_text TEXT,
    research_entry_summary TEXT,
    research_entry_why_it_matters TEXT,

    research_branch_id BIGINT
        REFERENCES tbl_research_branches(research_branch_id)
        ON DELETE SET NULL,

    research_mystery_id BIGINT
        REFERENCES tbl_research_mysteries(research_mystery_id)
        ON DELETE SET NULL,

    research_entry_status TEXT NOT NULL DEFAULT 'raw',

    research_entries_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    research_entry_updated_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- 4. RESEARCH PROMPTS
-- ============================================

CREATE TABLE tbl_research_prompts (
    research_prompt_id BIGSERIAL PRIMARY KEY,

    research_prompt_text TEXT NOT NULL,
    research_prompt_type TEXT NOT NULL,
    research_prompt_status TEXT NOT NULL DEFAULT 'pending',

    source_research_entry_id BIGINT
        REFERENCES tbl_research_entries(research_entry_id)
        ON DELETE SET NULL,

    research_prompt_priority_score NUMERIC(6,3),

    research_prompts_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- 5. AI OPERATIONS
-- ============================================

CREATE TABLE tbl_ai_operations (
    ai_operation_id BIGSERIAL PRIMARY KEY,

    research_entry_id BIGINT
        REFERENCES tbl_research_entries(research_entry_id)
        ON DELETE CASCADE,

    ai_operation_type TEXT NOT NULL,
    ai_model_name TEXT,
    ai_prompt_used TEXT,
    ai_response_text TEXT,
    ai_response_json JSONB,

    ai_operation_success BOOLEAN NOT NULL DEFAULT TRUE,
    ai_operation_error_message TEXT,

    ai_operations_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- INDEXES
-- ============================================

CREATE INDEX idx_tbl_research_entries_user_id
    ON tbl_research_entries (user_id);

CREATE INDEX idx_tbl_research_entries_branch_id
    ON tbl_research_entries (research_branch_id);

CREATE INDEX idx_tbl_research_entries_mystery_id
    ON tbl_research_entries (research_mystery_id);

CREATE INDEX idx_tbl_research_entries_created_ts
    ON tbl_research_entries (research_entries_timestamp DESC);
