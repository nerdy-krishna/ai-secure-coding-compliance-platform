--
-- PostgreSQL database dump
--

-- SCCAP current-schema baseline, captured from revision 4d5e6f708192.
-- This file contains schema and required bootstrap identities only. It never
-- contains deployment data or secrets. LangGraph checkpoint tables are owned
-- by the checkpointer and are intentionally excluded.

-- Dumped from database version 16.12 (Debian 16.12-1.pgdg13+1)
-- Dumped by pg_dump version 16.12 (Debian 16.12-1.pgdg13+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sccap_runtime') THEN
        CREATE ROLE sccap_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOINHERIT NOBYPASSRLS;
    END IF;
END
$$;

--
-- Name: auth_audit_events_block_modify(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.auth_audit_events_block_modify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        BEGIN
            RAISE EXCEPTION 'auth_audit_events is append-only; UPDATE/DELETE forbidden';
        END;
        $$;


--
-- Name: authorization_audit_events_block_modify(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.authorization_audit_events_block_modify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        BEGIN
            RAISE EXCEPTION 'authorization_audit_events is append-only; UPDATE/DELETE forbidden';
        END;
        $$;


--
-- Name: sccap_current_tenant_id(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sccap_current_tenant_id() RETURNS uuid
    LANGUAGE sql STABLE
    AS $$
          SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
        $$;


--
-- Name: sccap_enforce_finding_coverage_tenant(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sccap_enforce_finding_coverage_tenant() RETURNS trigger
    LANGUAGE plpgsql
    AS $$ DECLARE visible_count integer; BEGIN IF NEW.coverage_entry_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM scanner_coverage_entries c WHERE c.id = NEW.coverage_entry_id AND c.tenant_id = NEW.tenant_id) THEN RAISE EXCEPTION 'cross-tenant scanner coverage reference rejected'; END IF; IF NEW.coverage_entry_ids IS NOT NULL THEN SELECT count(*) INTO visible_count FROM scanner_coverage_entries c WHERE c.id = ANY(NEW.coverage_entry_ids) AND c.tenant_id = NEW.tenant_id; IF visible_count <> cardinality(NEW.coverage_entry_ids) THEN RAISE EXCEPTION 'cross-tenant scanner coverage references rejected'; END IF; END IF; RETURN NEW; END; $$;


--
-- Name: sccap_enforce_group_membership_tenant(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sccap_enforce_group_membership_tenant() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM user_groups g
                JOIN "user" u ON u.id = NEW.user_id
                WHERE g.id = NEW.group_id
                  AND g.tenant_id = u.tenant_id
            ) THEN
                RAISE EXCEPTION 'group membership tenant mismatch'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END
        $$;


--
-- Name: sccap_enforce_tenant_reference(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sccap_enforce_tenant_reference() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
        DECLARE
            expected_tenant uuid;
            local_reference text;
        BEGIN
            local_reference := to_jsonb(NEW) ->> TG_ARGV[2];
            IF local_reference IS NULL THEN
                RETURN NEW;
            END IF;
            EXECUTE format(
                'SELECT tenant_id FROM %I WHERE %I::text = $1',
                TG_ARGV[0], TG_ARGV[1]
            ) INTO expected_tenant USING local_reference;
            IF expected_tenant IS NULL THEN
                RAISE EXCEPTION 'tenant reference is missing or outside active scope';
            END IF;
            IF NEW.tenant_id IS NULL OR NEW.tenant_id = '00000000-0000-0000-0000-000000000001'::uuid THEN
                NEW.tenant_id := expected_tenant;
            ELSIF NEW.tenant_id <> expected_tenant THEN
                RAISE EXCEPTION 'cross-tenant reference rejected';
            END IF;
            RETURN NEW;
        END;
        $_$;


--
-- Name: sccap_has_system_scope(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sccap_has_system_scope() RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
          SELECT current_setting('app.system_scope', true) = 'on'
             AND current_setting('app.principal_kind', true) = 'system'
        $$;


--
-- Name: sccap_reject_finding_governance_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sccap_reject_finding_governance_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$ BEGIN
            IF pg_trigger_depth() > 1 THEN
                RETURN NEW;
            END IF;
            IF TG_TABLE_NAME = 'finding_lineage_records'
               AND TG_OP = 'UPDATE'
               AND OLD.finding_id IS NULL
               AND NEW.finding_id IS NOT NULL
               AND ROW(
                   OLD.id, OLD.tenant_id, OLD.project_id, OLD.scan_id,
                   OLD.attempt_id, OLD.predecessor_finding_id, OLD.fingerprint,
                   OLD.baseline_state, OLD.site_identity, OLD.exact_ranges,
                   OLD.dataflow, OLD.source_provenance,
                   OLD.producer_provenance, OLD.coverage_entry_ids,
                   OLD.evidence_object_ids, OLD.remediation_state, OLD.created_at
               ) IS NOT DISTINCT FROM ROW(
                   NEW.id, NEW.tenant_id, NEW.project_id, NEW.scan_id,
                   NEW.attempt_id, NEW.predecessor_finding_id, NEW.fingerprint,
                   NEW.baseline_state, NEW.site_identity, NEW.exact_ranges,
                   NEW.dataflow, NEW.source_provenance,
                   NEW.producer_provenance, NEW.coverage_entry_ids,
                   NEW.evidence_object_ids, NEW.remediation_state, NEW.created_at
               ) THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'finding governance evidence is immutable';
        END; $$;


--
-- Name: sccap_reject_integration_evidence_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sccap_reject_integration_evidence_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$ BEGIN
            RAISE EXCEPTION 'integration delivery evidence is immutable';
        END; $$;


--
-- Name: sccap_reject_provider_reconciliation_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sccap_reject_provider_reconciliation_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$ BEGIN
            RAISE EXCEPTION 'provider reconciliation evidence is immutable';
        END; $$;


--
-- Name: sccap_reject_rule_foundry_evidence_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sccap_reject_rule_foundry_evidence_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$ BEGIN
            IF pg_trigger_depth() > 1 AND TG_OP = 'UPDATE' THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'rule foundry signed evidence is immutable';
        END; $$;


--
-- Name: sccap_reject_usage_budget_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sccap_reject_usage_budget_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        BEGIN
            RAISE EXCEPTION 'usage budget history is immutable';
        END;
        $$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: agents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agents (
    id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text NOT NULL,
    domain_query jsonb NOT NULL
);


--
-- Name: approval_gates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.approval_gates (
    gate_id uuid NOT NULL,
    scan_id uuid NOT NULL,
    thread_id character varying(128) NOT NULL,
    checkpoint_id character varying(128),
    node_name character varying(100) NOT NULL,
    kind character varying(32) NOT NULL,
    sequence integer NOT NULL,
    display_name character varying(120) NOT NULL,
    purpose text NOT NULL,
    evidence_hash character varying(64) NOT NULL,
    evidence jsonb NOT NULL,
    state character varying(24) NOT NULL,
    version integer NOT NULL,
    decision boolean,
    override_critical_secret boolean DEFAULT false NOT NULL,
    actor_user_id integer,
    decision_idempotency_key character varying(128),
    resume_claimed_by character varying(255),
    resume_lease_expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    decided_at timestamp with time zone,
    completed_at timestamp with time zone,
    attempt_id uuid,
    CONSTRAINT ck_approval_gates_kind CHECK (((kind)::text = ANY ((ARRAY['prescan_approval'::character varying, 'profiling_approval'::character varying, 'cost_approval'::character varying])::text[]))),
    CONSTRAINT ck_approval_gates_state CHECK (((state)::text = ANY ((ARRAY['pending'::character varying, 'decided'::character varying, 'resume_claimed'::character varying, 'resumed'::character varying, 'completed'::character varying, 'expired'::character varying, 'cancelled'::character varying])::text[]))),
    CONSTRAINT ck_approval_gates_version_positive CHECK ((version > 0))
);

ALTER TABLE ONLY public.approval_gates FORCE ROW LEVEL SECURITY;


--
-- Name: auth_audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_audit_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    event character varying(64) NOT NULL,
    user_id integer,
    provider_id uuid,
    email_hash character varying(64),
    ip character varying(45),
    user_agent character varying(512),
    details jsonb,
    tenant_id uuid,
    actor_user_id integer,
    session_id uuid,
    outcome character varying(16) DEFAULT 'unknown'::character varying NOT NULL
);


--
-- Name: auth_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_sessions (
    id uuid NOT NULL,
    user_id integer NOT NULL,
    tenant_id uuid,
    provider_id uuid,
    auth_method character varying(32) NOT NULL,
    provider_session_hash character varying(64),
    assurance_level character varying(16) DEFAULT 'aal1'::character varying NOT NULL,
    credential_generation integer DEFAULT 0 NOT NULL,
    credential_secret_hash character varying(64) NOT NULL,
    authenticated_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    idle_expires_at timestamp with time zone NOT NULL,
    absolute_expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    revocation_reason character varying(64),
    ip_hash character varying(64),
    device_label character varying(128),
    active_tenant_id uuid,
    CONSTRAINT ck_auth_sessions_generation_nonnegative CHECK ((credential_generation >= 0)),
    CONSTRAINT ck_auth_sessions_idle_before_absolute CHECK ((idle_expires_at <= absolute_expires_at))
);


--
-- Name: authorization_action_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authorization_action_requests (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    requester_user_id integer NOT NULL,
    requester_permission character varying(96) NOT NULL,
    approver_permission character varying(96) NOT NULL,
    target_type character varying(64) NOT NULL,
    target_fingerprint character varying(64) NOT NULL,
    payload_digest character varying(64) NOT NULL,
    idempotency_key character varying(128) NOT NULL,
    status character varying(16) DEFAULT 'pending'::character varying NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    approver_user_id integer,
    decided_at timestamp with time zone,
    decision_reason character varying(500),
    executed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_authorization_action_requests_distinct_actor CHECK (((approver_user_id IS NULL) OR (approver_user_id <> requester_user_id))),
    CONSTRAINT ck_authorization_action_requests_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'rejected'::character varying, 'expired'::character varying, 'executed'::character varying, 'cancelled'::character varying])::text[])))
);

ALTER TABLE ONLY public.authorization_action_requests FORCE ROW LEVEL SECURITY;


--
-- Name: authorization_audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authorization_audit_events (
    id uuid NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id uuid,
    principal_kind character varying(32) NOT NULL,
    principal_id character varying(128) NOT NULL,
    permission character varying(96) NOT NULL,
    resource_type character varying(64) NOT NULL,
    target_fingerprint character varying(64),
    outcome character varying(16) NOT NULL,
    reason_code character varying(64) NOT NULL,
    correlation_id character varying(128) NOT NULL,
    action_request_id uuid,
    approver_principal_id character varying(128),
    CONSTRAINT ck_authorization_audit_events_outcome CHECK (((outcome)::text = ANY ((ARRAY['allowed'::character varying, 'denied'::character varying, 'requested'::character varying, 'approved'::character varying, 'rejected'::character varying, 'executed'::character varying, 'failed'::character varying])::text[]))),
    CONSTRAINT ck_authorization_audit_events_principal_kind CHECK (((principal_kind)::text = ANY ((ARRAY['human'::character varying, 'service_principal'::character varying, 'system'::character varying])::text[])))
);


--
-- Name: chat_messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_messages (
    id bigint NOT NULL,
    session_id uuid NOT NULL,
    role character varying(20) NOT NULL,
    content text NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    cost numeric(10,8),
    expires_at timestamp with time zone
);

ALTER TABLE ONLY public.chat_messages FORCE ROW LEVEL SECURITY;


--
-- Name: chat_messages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.chat_messages ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.chat_messages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: chat_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_sessions (
    id uuid NOT NULL,
    user_id integer NOT NULL,
    project_id uuid,
    title character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    llm_config_id uuid,
    frameworks character varying[],
    tenant_id uuid DEFAULT '00000000-0000-0000-0000-000000000001'::uuid NOT NULL
);

ALTER TABLE ONLY public.chat_sessions FORCE ROW LEVEL SECURITY;


--
-- Name: code_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.code_snapshots (
    id uuid NOT NULL,
    scan_id uuid NOT NULL,
    snapshot_type character varying(50) NOT NULL,
    file_map jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.code_snapshots FORCE ROW LEVEL SECURITY;


--
-- Name: cwe_details; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cwe_details (
    id character varying(20) NOT NULL,
    name text NOT NULL,
    abstraction character varying(50),
    description text NOT NULL,
    rag_document_text text NOT NULL
);


--
-- Name: cwe_owasp_mappings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cwe_owasp_mappings (
    cwe_id character varying(20) NOT NULL,
    owasp_category_id character varying(10) NOT NULL,
    owasp_category_name character varying(255) NOT NULL,
    owasp_rank integer NOT NULL
);


--
-- Name: evidence_deletion_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.evidence_deletion_outbox (
    id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    attempts integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    processed_at timestamp with time zone,
    last_error text
);

ALTER TABLE ONLY public.evidence_deletion_outbox FORCE ROW LEVEL SECURITY;


--
-- Name: evidence_governance_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.evidence_governance_events (
    id bigint NOT NULL,
    scan_id uuid,
    attempt_id uuid,
    evidence_id uuid,
    tenant_id uuid DEFAULT '00000000-0000-0000-0000-000000000001'::uuid NOT NULL,
    action character varying(64) NOT NULL,
    actor_user_id integer,
    reason text,
    correlation_id character varying(255),
    details jsonb NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.evidence_governance_events FORCE ROW LEVEL SECURITY;


--
-- Name: evidence_governance_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.evidence_governance_events ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.evidence_governance_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: evidence_manifests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.evidence_manifests (
    id uuid NOT NULL,
    scan_id uuid,
    attempt_id uuid,
    generation integer NOT NULL,
    previous_manifest_sha256 character varying(64),
    manifest_sha256 character varying(64) NOT NULL,
    entries jsonb NOT NULL,
    finalized boolean DEFAULT false NOT NULL,
    actor_user_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.evidence_manifests FORCE ROW LEVEL SECURITY;


--
-- Name: evidence_objects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.evidence_objects (
    id uuid NOT NULL,
    scan_id uuid,
    attempt_id uuid,
    tenant_id uuid DEFAULT '00000000-0000-0000-0000-000000000001'::uuid NOT NULL,
    artifact_type character varying(64) NOT NULL,
    version integer NOT NULL,
    object_key character varying(1024) NOT NULL,
    object_version character varying(255) NOT NULL,
    media_type character varying(255) NOT NULL,
    plaintext_size bigint NOT NULL,
    ciphertext_size bigint NOT NULL,
    plaintext_sha256 character varying(64) NOT NULL,
    ciphertext_sha256 character varying(64) NOT NULL,
    producer jsonb NOT NULL,
    actor_user_id integer,
    encryption_algorithm character varying(64) NOT NULL,
    key_provider character varying(32) NOT NULL,
    key_id character varying(512) NOT NULL,
    wrapped_data_key bytea NOT NULL,
    nonce bytea NOT NULL,
    aad_sha256 character varying(64) NOT NULL,
    retention_policy character varying(64) NOT NULL,
    retain_until timestamp with time zone NOT NULL,
    legal_hold boolean DEFAULT false NOT NULL,
    state character varying(24) NOT NULL,
    legacy_artifact_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT ck_evidence_objects_state CHECK (((state)::text = ANY ((ARRAY['available'::character varying, 'deletion_pending'::character varying, 'deleted'::character varying])::text[])))
);

ALTER TABLE ONLY public.evidence_objects FORCE ROW LEVEL SECURITY;


--
-- Name: federation_replay_markers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_replay_markers (
    id uuid NOT NULL,
    provider_id uuid NOT NULL,
    kind character varying(32) NOT NULL,
    message_hash character varying(64) NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: finding_disposition_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_disposition_events (
    id bigint NOT NULL,
    finding_id bigint NOT NULL,
    old_disposition character varying(20) NOT NULL,
    new_disposition character varying(20) NOT NULL,
    actor_user_id integer,
    note text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.finding_disposition_events FORCE ROW LEVEL SECURITY;


--
-- Name: finding_disposition_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.finding_disposition_events ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.finding_disposition_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: finding_fix_candidates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_fix_candidates (
    candidate_id uuid NOT NULL,
    scan_id uuid NOT NULL,
    raw_finding_id uuid NOT NULL,
    canonical_finding_id uuid,
    source_snapshot_hash character varying(64) NOT NULL,
    anchor_fingerprint character varying(64) NOT NULL,
    patch_fingerprint character varying(64) NOT NULL,
    file_path text NOT NULL,
    line_number integer NOT NULL,
    suggestion jsonb NOT NULL,
    disposition character varying(20) NOT NULL,
    decision_reason text,
    contributing_agents jsonb NOT NULL,
    contributing_models jsonb NOT NULL,
    validation_status character varying(20) NOT NULL,
    is_applied boolean DEFAULT false NOT NULL,
    batch integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_range jsonb,
    context_fingerprint character varying(64),
    patch_hunk_id uuid,
    applicability_status character varying(32) DEFAULT 'unresolved'::character varying NOT NULL,
    language character varying(64),
    symbol character varying(512),
    required_imports jsonb DEFAULT '[]'::jsonb NOT NULL,
    required_dependencies jsonb DEFAULT '[]'::jsonb NOT NULL,
    configuration_changes jsonb DEFAULT '[]'::jsonb NOT NULL,
    migration_changes jsonb DEFAULT '[]'::jsonb NOT NULL,
    manual_steps jsonb DEFAULT '[]'::jsonb NOT NULL,
    CONSTRAINT ck_finding_fix_candidates_disposition CHECK (((disposition)::text = ANY ((ARRAY['pending'::character varying, 'selected'::character varying, 'alternative'::character varying, 'duplicate'::character varying, 'conflict'::character varying, 'rejected'::character varying])::text[]))),
    CONSTRAINT ck_finding_fix_candidates_validation_status CHECK (((validation_status)::text = ANY ((ARRAY['not_run'::character varying, 'passed'::character varying, 'failed'::character varying])::text[])))
);

ALTER TABLE ONLY public.finding_fix_candidates FORCE ROW LEVEL SECURITY;


--
-- Name: finding_lineage_records; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_lineage_records (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid,
    scan_id uuid,
    attempt_id uuid,
    finding_id bigint,
    predecessor_finding_id bigint,
    fingerprint character varying(64) NOT NULL,
    baseline_state character varying(16) NOT NULL,
    exact_ranges jsonb DEFAULT '[]'::jsonb NOT NULL,
    dataflow jsonb DEFAULT '{}'::jsonb NOT NULL,
    source_provenance jsonb DEFAULT '{}'::jsonb NOT NULL,
    producer_provenance jsonb DEFAULT '{}'::jsonb NOT NULL,
    coverage_entry_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    evidence_object_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    remediation_state jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    site_identity character varying(64) NOT NULL,
    CONSTRAINT ck_finding_lineage_baseline_state CHECK (((baseline_state)::text = ANY ((ARRAY['new'::character varying, 'fixed'::character varying, 'unchanged'::character varying, 'reintroduced'::character varying])::text[])))
);

ALTER TABLE ONLY public.finding_lineage_records FORCE ROW LEVEL SECURITY;


--
-- Name: finding_policy_evaluations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_policy_evaluations (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid,
    scan_id uuid,
    attempt_id uuid,
    policy_version_id uuid NOT NULL,
    outcome character varying(8) NOT NULL,
    coverage_complete boolean NOT NULL,
    blocking_fingerprints character varying(64)[] DEFAULT '{}'::character varying[] NOT NULL,
    waived_fingerprints character varying(64)[] DEFAULT '{}'::character varying[] NOT NULL,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_finding_policy_evaluation_outcome CHECK (((outcome)::text = ANY ((ARRAY['pass'::character varying, 'fail'::character varying])::text[])))
);

ALTER TABLE ONLY public.finding_policy_evaluations FORCE ROW LEVEL SECURITY;


--
-- Name: finding_policy_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_policy_versions (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    version integer NOT NULL,
    minimum_severity character varying(16) NOT NULL,
    minimum_confidence character varying(16) NOT NULL,
    require_complete_coverage boolean NOT NULL,
    allow_waivers boolean NOT NULL,
    minimum_waiver_remaining_hours integer NOT NULL,
    actor_user_id integer,
    reason text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_finding_policy_minimum_confidence CHECK (((minimum_confidence)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying])::text[]))),
    CONSTRAINT ck_finding_policy_minimum_severity CHECK (((minimum_severity)::text = ANY ((ARRAY['informational'::character varying, 'low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT ck_finding_policy_waiver_hours CHECK ((minimum_waiver_remaining_hours >= 0))
);

ALTER TABLE ONLY public.finding_policy_versions FORCE ROW LEVEL SECURITY;


--
-- Name: finding_waiver_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_waiver_events (
    id bigint NOT NULL,
    tenant_id uuid NOT NULL,
    waiver_id uuid NOT NULL,
    action character varying(16) NOT NULL,
    actor_user_id integer,
    reason text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_finding_waiver_event_action CHECK (((action)::text = ANY ((ARRAY['granted'::character varying, 'revoked'::character varying, 'expired'::character varying])::text[])))
);

ALTER TABLE ONLY public.finding_waiver_events FORCE ROW LEVEL SECURITY;


--
-- Name: finding_waiver_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.finding_waiver_events ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.finding_waiver_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: finding_waivers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_waivers (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid,
    scan_id uuid,
    finding_id bigint,
    fingerprint character varying(64) NOT NULL,
    scope character varying(16) NOT NULL,
    scope_value character varying(255) NOT NULL,
    reason text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    actor_user_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_finding_waiver_future_expiry CHECK ((expires_at > created_at)),
    CONSTRAINT ck_finding_waiver_scope CHECK (((scope)::text = ANY ((ARRAY['finding'::character varying, 'fingerprint'::character varying, 'project'::character varying])::text[])))
);

ALTER TABLE ONLY public.finding_waivers FORCE ROW LEVEL SECURITY;


--
-- Name: findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.findings (
    id bigint NOT NULL,
    scan_id uuid NOT NULL,
    file_path text NOT NULL,
    line_number integer,
    title character varying(512) NOT NULL,
    description text,
    severity character varying(50),
    remediation text,
    cwe character varying(50),
    fixes jsonb,
    confidence character varying(50),
    "references" jsonb,
    cvss_score numeric(3,1),
    cvss_vector character varying(100),
    is_applied_in_remediation boolean DEFAULT false NOT NULL,
    corroborating_agents jsonb,
    source character varying(32),
    cve_id character varying(64),
    fix_verified boolean,
    tenant_id uuid DEFAULT '00000000-0000-0000-0000-000000000001'::uuid NOT NULL,
    vulnerable_snippet text,
    affected_locations jsonb,
    cross_file_status character varying(20),
    cross_file_rationale text,
    detected_by_llms jsonb,
    disposition character varying(20) DEFAULT 'open'::character varying NOT NULL,
    disposition_by integer,
    disposition_at timestamp with time zone,
    disposition_note text,
    finding_bucket character varying(16) NOT NULL,
    batch integer NOT NULL,
    raw_finding_id uuid,
    canonical_finding_id uuid,
    contributing_raw_finding_ids uuid[],
    source_snapshot_hash character varying(64),
    fix_selection_status character varying(32),
    scanner_rule_id character varying(512),
    coverage_entry_id uuid,
    coverage_entry_ids uuid[],
    CONSTRAINT ck_findings_description_maxlen CHECK ((length(description) <= 65535)),
    CONSTRAINT ck_findings_disposition CHECK (((disposition)::text = ANY ((ARRAY['open'::character varying, 'confirmed'::character varying, 'false_positive'::character varying, 'remediated'::character varying, 'risk_accepted'::character varying])::text[]))),
    CONSTRAINT ck_findings_remediation_maxlen CHECK ((length(remediation) <= 65535))
);

ALTER TABLE ONLY public.findings FORCE ROW LEVEL SECURITY;


--
-- Name: findings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.findings ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.findings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: framework_agent_mappings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.framework_agent_mappings (
    framework_id uuid NOT NULL,
    agent_id uuid NOT NULL
);


--
-- Name: frameworks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.frameworks (
    id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text NOT NULL,
    source_url text
);


--
-- Name: governance_legal_holds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.governance_legal_holds (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    scope_type character varying(24) NOT NULL,
    scope_id character varying(128) NOT NULL,
    reason text NOT NULL,
    placed_by_user_id integer NOT NULL,
    placed_at timestamp with time zone DEFAULT now() NOT NULL,
    released_by_user_id integer,
    released_at timestamp with time zone,
    release_reason text,
    CONSTRAINT ck_governance_legal_hold_scope CHECK (((scope_type)::text = ANY ((ARRAY['tenant'::character varying, 'project'::character varying, 'scan'::character varying, 'attempt'::character varying, 'evidence'::character varying])::text[])))
);

ALTER TABLE ONLY public.governance_legal_holds FORCE ROW LEVEL SECURITY;


--
-- Name: governance_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.governance_operations (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    kind character varying(12) NOT NULL,
    status character varying(24) DEFAULT 'prepared'::character varying NOT NULL,
    idempotency_key character varying(64) NOT NULL,
    scope jsonb NOT NULL,
    policy_snapshot jsonb NOT NULL,
    manifest jsonb DEFAULT '{}'::jsonb NOT NULL,
    manifest_sha256 character varying(64),
    signature_b64 text,
    signature_algorithm character varying(64),
    signing_key_id character varying(512),
    failure_code character varying(64),
    requested_by_user_id integer NOT NULL,
    reason text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    CONSTRAINT ck_governance_operation_kind CHECK (((kind)::text = ANY ((ARRAY['export'::character varying, 'delete'::character varying])::text[]))),
    CONSTRAINT ck_governance_operation_status CHECK (((status)::text = ANY ((ARRAY['prepared'::character varying, 'executing'::character varying, 'completed'::character varying, 'failed'::character varying, 'blocked_legal_hold'::character varying])::text[])))
);

ALTER TABLE ONLY public.governance_operations FORCE ROW LEVEL SECURITY;


--
-- Name: governance_store_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.governance_store_actions (
    id uuid NOT NULL,
    operation_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    store character varying(20) NOT NULL,
    status character varying(16) DEFAULT 'pending'::character varying NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    lease_expires_at timestamp with time zone,
    result jsonb DEFAULT '{}'::jsonb NOT NULL,
    result_sha256 character varying(64),
    last_error_code character varying(64),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    applied_at timestamp with time zone,
    verified_at timestamp with time zone,
    CONSTRAINT ck_governance_store_action_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'leased'::character varying, 'applied'::character varying, 'verified'::character varying, 'failed'::character varying])::text[]))),
    CONSTRAINT ck_governance_store_action_store CHECK (((store)::text = ANY ((ARRAY['postgres'::character varying, 'object'::character varying, 'qdrant'::character varying, 'observability'::character varying])::text[])))
);

ALTER TABLE ONLY public.governance_store_actions FORCE ROW LEVEL SECURITY;


--
-- Name: integration_delivery_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_delivery_audit (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    outbox_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    attempt integer NOT NULL,
    outcome character varying(24) NOT NULL,
    http_status integer,
    evidence_digest character varying(64) NOT NULL,
    response_excerpt_redacted character varying(1024),
    error_code character varying(64),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_integration_delivery_audit_attempt CHECK ((attempt > 0))
);

ALTER TABLE ONLY public.integration_delivery_audit FORCE ROW LEVEL SECURITY;


--
-- Name: integration_finding_tickets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_finding_tickets (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    canonical_root_id character varying(128) NOT NULL,
    external_key character varying(128) NOT NULL,
    external_url character varying(1024),
    status character varying(64) NOT NULL,
    waiver_expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.integration_finding_tickets FORCE ROW LEVEL SECURITY;


--
-- Name: integration_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_grants (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    feature character varying(40) NOT NULL,
    scope jsonb NOT NULL,
    scope_digest character varying(64) NOT NULL,
    created_by_user_id integer NOT NULL,
    revoked_by_user_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT ck_integration_grant_feature CHECK (((feature)::text = ANY ((ARRAY['repository_contents_read'::character varying, 'security_events_write'::character varying, 'webhook_metadata_read'::character varying, 'ticket_sync'::character varying, 'siem_emit'::character varying])::text[])))
);

ALTER TABLE ONLY public.integration_grants FORCE ROW LEVEL SECURITY;


--
-- Name: integration_inbound_receipts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_inbound_receipts (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    source_event_id character varying(128) NOT NULL,
    nonce character varying(128) NOT NULL,
    event_type character varying(96) NOT NULL,
    payload_digest character varying(64) NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.integration_inbound_receipts FORCE ROW LEVEL SECURITY;


--
-- Name: integration_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_outbox (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    event_type character varying(96) NOT NULL,
    envelope_version integer DEFAULT 1 NOT NULL,
    idempotency_key character varying(64) NOT NULL,
    nonce character varying(128) NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    payload_redacted jsonb NOT NULL,
    payload_digest character varying(64) NOT NULL,
    state character varying(16) DEFAULT 'pending'::character varying NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 8 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_expires_at timestamp with time zone,
    delivered_at timestamp with time zone,
    last_error_code character varying(64),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    source_event_key character varying(128),
    CONSTRAINT ck_integration_outbox_attempts CHECK (((attempts >= 0) AND ((max_attempts >= 1) AND (max_attempts <= 20)))),
    CONSTRAINT ck_integration_outbox_state CHECK (((state)::text = ANY ((ARRAY['pending'::character varying, 'delivering'::character varying, 'retry'::character varying, 'delivered'::character varying, 'dead_letter'::character varying])::text[])))
);

ALTER TABLE ONLY public.integration_outbox FORCE ROW LEVEL SECURITY;


--
-- Name: integration_service_principals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_service_principals (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    kind character varying(32) NOT NULL,
    display_name character varying(120) NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    secrets_encrypted bytea NOT NULL,
    secret_fingerprint character varying(64) NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_by_user_id integer NOT NULL,
    revoked_by_user_id integer,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_integration_service_principal_kind CHECK (((kind)::text = ANY ((ARRAY['github_app'::character varying, 'jira_cloud'::character varying, 'siem_webhook'::character varying])::text[])))
);

ALTER TABLE ONLY public.integration_service_principals FORCE ROW LEVEL SECURITY;


--
-- Name: integration_source_submissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_source_submissions (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    scan_id uuid NOT NULL,
    provider character varying(24) NOT NULL,
    commit_sha character varying(64) NOT NULL,
    ref character varying(255) NOT NULL,
    repository_slug character varying(255) NOT NULL,
    trusted_context boolean NOT NULL,
    created_by_user_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_integration_source_submission_provider CHECK (((provider)::text = ANY ((ARRAY['github'::character varying, 'gitlab'::character varying, 'azure_devops'::character varying, 'bitbucket'::character varying])::text[])))
);

ALTER TABLE ONLY public.integration_source_submissions FORCE ROW LEVEL SECURITY;


--
-- Name: integration_ticket_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_ticket_history (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    ticket_id uuid NOT NULL,
    from_status character varying(64),
    to_status character varying(64) NOT NULL,
    reason character varying(96) NOT NULL,
    event_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.integration_ticket_history FORCE ROW LEVEL SECURITY;


--
-- Name: llm_call_reservations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.llm_call_reservations (
    id uuid NOT NULL,
    idempotency_key character varying(512) NOT NULL,
    owner_token uuid NOT NULL,
    scan_id uuid,
    attempt_id uuid,
    llm_config_id uuid,
    stage character varying(100) NOT NULL,
    status character varying(20) DEFAULT 'reserved'::character varying NOT NULL,
    usage_event_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT ck_llm_call_reservations_status CHECK (((status)::text = ANY ((ARRAY['reserved'::character varying, 'completed'::character varying, 'failed'::character varying])::text[])))
);

ALTER TABLE ONLY public.llm_call_reservations FORCE ROW LEVEL SECURITY;


--
-- Name: llm_configurations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.llm_configurations (
    id uuid NOT NULL,
    name character varying NOT NULL,
    provider character varying NOT NULL,
    model_name character varying NOT NULL,
    encrypted_api_key text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    input_cost_per_million numeric(10,6) DEFAULT 0.000000 NOT NULL,
    output_cost_per_million numeric(10,6) DEFAULT 0.000000 NOT NULL,
    tokenizer character varying(100),
    requests_per_minute integer,
    tokens_per_minute integer,
    max_prompt_tokens integer,
    base_url character varying(512)
);


--
-- Name: llm_interactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.llm_interactions (
    id bigint NOT NULL,
    scan_id uuid,
    chat_message_id bigint,
    agent_name character varying(100) NOT NULL,
    prompt_template_name character varying(100),
    prompt_context jsonb,
    raw_response text NOT NULL,
    parsed_output jsonb,
    error text,
    cost numeric(10,8),
    input_tokens integer,
    output_tokens integer,
    total_tokens integer,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    file_path text,
    expires_at timestamp with time zone,
    llm_config_id uuid,
    usage_event_id uuid
);

ALTER TABLE ONLY public.llm_interactions FORCE ROW LEVEL SECURITY;


--
-- Name: llm_interactions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.llm_interactions ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.llm_interactions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: llm_price_overrides; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.llm_price_overrides (
    id uuid NOT NULL,
    llm_config_id uuid NOT NULL,
    rates jsonb NOT NULL,
    currency character varying(3) NOT NULL,
    source character varying(255) NOT NULL,
    effective_from timestamp with time zone NOT NULL,
    effective_to timestamp with time zone,
    created_by_user_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_llm_price_override_interval CHECK (((effective_to IS NULL) OR (effective_to > effective_from)))
);


--
-- Name: llm_usage_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.llm_usage_events (
    id uuid NOT NULL,
    idempotency_key character varying(512) NOT NULL,
    operation_kind character varying(32) NOT NULL,
    operation_id character varying(128) NOT NULL,
    scan_id uuid,
    chat_session_id uuid,
    rag_job_id uuid,
    scan_task_id uuid,
    stage character varying(100) NOT NULL,
    agent_name character varying(100) NOT NULL,
    llm_config_id uuid,
    user_id integer,
    tenant_id uuid DEFAULT '00000000-0000-0000-0000-000000000001'::uuid NOT NULL,
    group_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    provider character varying(64) NOT NULL,
    requested_model character varying(255) NOT NULL,
    resolved_models character varying(255)[] DEFAULT '{}'::character varying[] NOT NULL,
    request_count integer NOT NULL,
    tool_call_count integer NOT NULL,
    input_tokens bigint NOT NULL,
    output_tokens bigint NOT NULL,
    total_tokens bigint NOT NULL,
    cache_read_tokens bigint NOT NULL,
    cache_write_tokens bigint NOT NULL,
    reasoning_tokens bigint NOT NULL,
    usage_source character varying(20) NOT NULL,
    quality_state character varying(20) NOT NULL,
    cost_status character varying(20) NOT NULL,
    currency character varying(3),
    total_cost numeric(30,12),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    attempt_id uuid,
    CONSTRAINT ck_llm_usage_events_cost_status CHECK (((cost_status)::text = ANY ((ARRAY['exact'::character varying, 'estimated'::character varying, 'unknown'::character varying, 'reconciled'::character varying])::text[]))),
    CONSTRAINT ck_llm_usage_events_quality CHECK (((quality_state)::text = ANY ((ARRAY['exact'::character varying, 'normalized'::character varying, 'estimated'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT ck_llm_usage_events_source CHECK (((usage_source)::text = ANY ((ARRAY['provider'::character varying, 'estimated'::character varying, 'reconciled'::character varying])::text[])))
);

ALTER TABLE ONLY public.llm_usage_events FORCE ROW LEVEL SECURITY;


--
-- Name: llm_usage_line_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.llm_usage_line_items (
    id uuid NOT NULL,
    usage_request_id uuid NOT NULL,
    line_index integer NOT NULL,
    category character varying(100) NOT NULL,
    quantity numeric(30,6) NOT NULL,
    unit character varying(50) NOT NULL,
    rate numeric(30,12) NOT NULL,
    modifier numeric(20,12) NOT NULL,
    currency character varying(3) NOT NULL,
    amount numeric(30,12) NOT NULL,
    source character varying(255) NOT NULL,
    effective_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.llm_usage_line_items FORCE ROW LEVEL SECURITY;


--
-- Name: llm_usage_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.llm_usage_requests (
    id uuid NOT NULL,
    usage_event_id uuid NOT NULL,
    request_index integer NOT NULL,
    provider_response_id character varying(512),
    provider character varying(64) NOT NULL,
    requested_model character varying(255) NOT NULL,
    resolved_model character varying(255),
    api_flavor character varying(64),
    service_tier character varying(64),
    is_batch boolean,
    region character varying(128),
    input_tokens bigint NOT NULL,
    output_tokens bigint NOT NULL,
    total_tokens bigint NOT NULL,
    uncached_input_tokens bigint NOT NULL,
    cache_read_tokens bigint NOT NULL,
    cache_write_tokens bigint NOT NULL,
    reasoning_tokens bigint NOT NULL,
    input_audio_tokens bigint NOT NULL,
    output_audio_tokens bigint NOT NULL,
    image_input_tokens bigint NOT NULL,
    image_output_tokens bigint NOT NULL,
    tool_request_tokens bigint NOT NULL,
    provider_usage jsonb NOT NULL,
    usage_source character varying(20) NOT NULL,
    quality_state character varying(20) NOT NULL,
    quality_reasons character varying(100)[] DEFAULT '{}'::character varying[] NOT NULL,
    price_snapshot jsonb,
    cost_status character varying(20) NOT NULL,
    currency character varying(3),
    total_cost numeric(30,12),
    received_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.llm_usage_requests FORCE ROW LEVEL SECURITY;


--
-- Name: oauth_accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_accounts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id integer NOT NULL,
    provider_id uuid NOT NULL,
    account_id character varying(320) NOT NULL,
    account_email character varying(320) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    idp_token_expires_at timestamp with time zone,
    tenant_id uuid
);


--
-- Name: offline_bundle_deployments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.offline_bundle_deployments (
    id uuid NOT NULL,
    sequence integer NOT NULL,
    bundle_version character varying(96) NOT NULL,
    bundle_sha256 character varying(64) NOT NULL,
    manifest_sha256 character varying(64) NOT NULL,
    signature_b64 text NOT NULL,
    signature_algorithm character varying(64) NOT NULL,
    signing_key_id character varying(512) NOT NULL,
    status character varying(16) NOT NULL,
    previous_deployment_id uuid,
    manifest jsonb NOT NULL,
    actor character varying(128) NOT NULL,
    reason text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_offline_bundle_deployment_status CHECK (((status)::text = ANY ((ARRAY['staged'::character varying, 'active'::character varying, 'rolled_back'::character varying, 'rejected'::character varying])::text[])))
);


--
-- Name: projects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.projects (
    id uuid NOT NULL,
    user_id integer NOT NULL,
    name character varying(255) NOT NULL,
    repository_url text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id uuid DEFAULT '00000000-0000-0000-0000-000000000001'::uuid NOT NULL
);

ALTER TABLE ONLY public.projects FORCE ROW LEVEL SECURITY;


--
-- Name: prompt_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.prompt_templates (
    id uuid NOT NULL,
    name character varying(255) NOT NULL,
    agent_name character varying(100),
    version integer NOT NULL,
    template_text text NOT NULL,
    template_type character varying(50) DEFAULT 'QUICK_AUDIT'::character varying NOT NULL,
    variant character varying(32) DEFAULT 'generic'::character varying NOT NULL
);


--
-- Name: provider_billing_connectors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.provider_billing_connectors (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    provider character varying(32) NOT NULL,
    display_name character varying(100) NOT NULL,
    credentials_encrypted bytea NOT NULL,
    provider_project_ids character varying(255)[] DEFAULT '{}'::character varying[] NOT NULL,
    verified_scopes character varying(100)[] DEFAULT '{}'::character varying[] NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    absolute_tolerance_micro_usd bigint DEFAULT '1000'::bigint NOT NULL,
    percentage_tolerance numeric(7,4) DEFAULT 1.0000 NOT NULL,
    lookback_minutes integer DEFAULT 180 NOT NULL,
    poll_interval_minutes integer DEFAULT 60 NOT NULL,
    next_run_at timestamp with time zone,
    last_run_at timestamp with time zone,
    created_by_user_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_provider_billing_connector_absolute_tolerance CHECK ((absolute_tolerance_micro_usd >= 0)),
    CONSTRAINT ck_provider_billing_connector_lookback CHECK (((lookback_minutes >= 0) AND (lookback_minutes <= 10080))),
    CONSTRAINT ck_provider_billing_connector_percentage_tolerance CHECK (((percentage_tolerance >= (0)::numeric) AND (percentage_tolerance <= (100)::numeric))),
    CONSTRAINT ck_provider_billing_connector_poll CHECK (((poll_interval_minutes >= 15) AND (poll_interval_minutes <= 10080))),
    CONSTRAINT ck_provider_billing_connector_provider CHECK (((provider)::text = 'openai'::text))
);

ALTER TABLE ONLY public.provider_billing_connectors FORCE ROW LEVEL SECURITY;


--
-- Name: provider_reconciliation_adjustments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.provider_reconciliation_adjustments (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    kind character varying(40) NOT NULL,
    amount_micro_usd bigint NOT NULL,
    currency character varying(3) DEFAULT 'USD'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.provider_reconciliation_adjustments FORCE ROW LEVEL SECURITY;


--
-- Name: provider_reconciliation_alert_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.provider_reconciliation_alert_outbox (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    severity character varying(16) NOT NULL,
    payload jsonb NOT NULL,
    state character varying(16) DEFAULT 'pending'::character varying NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    published_at timestamp with time zone,
    error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_provider_reconciliation_alert_state CHECK (((state)::text = ANY ((ARRAY['pending'::character varying, 'published'::character varying, 'failed'::character varying])::text[])))
);

ALTER TABLE ONLY public.provider_reconciliation_alert_outbox FORCE ROW LEVEL SECURITY;


--
-- Name: provider_reconciliation_evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.provider_reconciliation_evidence (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    dimension_key character varying(64) NOT NULL,
    classification character varying(40) NOT NULL,
    canonical_micro_usd bigint NOT NULL,
    provider_micro_usd bigint NOT NULL,
    variance_micro_usd bigint NOT NULL,
    within_tolerance boolean NOT NULL,
    canonical_tokens jsonb NOT NULL,
    provider_tokens jsonb NOT NULL,
    normalized_dimensions jsonb NOT NULL,
    provider_item_ids character varying(255)[] DEFAULT '{}'::character varying[] NOT NULL,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.provider_reconciliation_evidence FORCE ROW LEVEL SECURITY;


--
-- Name: provider_reconciliation_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.provider_reconciliation_runs (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    idempotency_key character varying(512) NOT NULL,
    window_start timestamp with time zone NOT NULL,
    window_end timestamp with time zone NOT NULL,
    status character varying(16) NOT NULL,
    trigger_kind character varying(16) NOT NULL,
    canonical_micro_usd bigint DEFAULT '0'::bigint NOT NULL,
    provider_micro_usd bigint DEFAULT '0'::bigint NOT NULL,
    variance_micro_usd bigint DEFAULT '0'::bigint NOT NULL,
    unresolved_micro_usd bigint DEFAULT '0'::bigint NOT NULL,
    coverage_percent numeric(7,4) DEFAULT '0'::numeric NOT NULL,
    compared_dimensions integer DEFAULT 0 NOT NULL,
    unresolved_dimensions integer DEFAULT 0 NOT NULL,
    provider_pages integer DEFAULT 0 NOT NULL,
    error_code character varying(64),
    created_by_user_id integer,
    started_at timestamp with time zone NOT NULL,
    completed_at timestamp with time zone NOT NULL,
    CONSTRAINT ck_provider_reconciliation_run_status CHECK (((status)::text = ANY ((ARRAY['completed'::character varying, 'failed'::character varying])::text[]))),
    CONSTRAINT ck_provider_reconciliation_run_window CHECK ((window_end > window_start))
);

ALTER TABLE ONLY public.provider_reconciliation_runs FORCE ROW LEVEL SECURITY;


--
-- Name: push_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.push_subscriptions (
    id bigint NOT NULL,
    user_id integer NOT NULL,
    endpoint text NOT NULL,
    p256dh text NOT NULL,
    auth text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.push_subscriptions FORCE ROW LEVEL SECURITY;


--
-- Name: push_subscriptions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.push_subscriptions ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.push_subscriptions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: rag_preprocessing_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rag_preprocessing_jobs (
    id uuid NOT NULL,
    user_id integer NOT NULL,
    framework_name character varying(255) NOT NULL,
    llm_config_id uuid NOT NULL,
    original_file_hash character varying(64) NOT NULL,
    status character varying(50) NOT NULL,
    estimated_cost jsonb,
    actual_cost numeric(10,8),
    processed_documents jsonb,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    raw_content bytea,
    expires_at timestamp with time zone,
    raw_content_retention_consent boolean DEFAULT false NOT NULL
);

ALTER TABLE ONLY public.rag_preprocessing_jobs FORCE ROW LEVEL SECURITY;


--
-- Name: role_assignments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_assignments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id integer NOT NULL,
    tenant_id uuid,
    role_key character varying(32) NOT NULL,
    created_by_user_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_role_assignments_builtin_role CHECK (((role_key)::text = ANY ((ARRAY['platform_owner'::character varying, 'tenant_admin'::character varying, 'security_approver'::character varying, 'analyst'::character varying, 'developer'::character varying, 'auditor'::character varying])::text[]))),
    CONSTRAINT ck_role_assignments_scope CHECK (((((role_key)::text = 'platform_owner'::text) AND (tenant_id IS NULL)) OR (((role_key)::text <> 'platform_owner'::text) AND (tenant_id IS NOT NULL))))
);

ALTER TABLE ONLY public.role_assignments FORCE ROW LEVEL SECURITY;


--
-- Name: rule_foundry_candidates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rule_foundry_candidates (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    source_finding_id bigint,
    source_scan_id uuid,
    source_attempt_id uuid,
    registry_kind character varying(16) NOT NULL,
    predicate_kind character varying(32) NOT NULL,
    static_representable boolean NOT NULL,
    non_representable_reason text,
    stable_identity character varying(64) NOT NULL,
    status character varying(24) DEFAULT 'pending_review'::character varying NOT NULL,
    severity character varying(16) NOT NULL,
    cwe character varying(50),
    normalized_evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    fixtures jsonb DEFAULT '{}'::jsonb NOT NULL,
    creator_user_id integer,
    reviewer_user_id integer,
    promoter_user_id integer,
    expires_at timestamp with time zone NOT NULL,
    reviewed_at timestamp with time zone,
    promoted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_rule_foundry_candidate_predicate CHECK (((predicate_kind)::text = ANY ((ARRAY['ast'::character varying, 'taint'::character varying, 'dependency_advisory'::character varying, 'secret_pattern'::character varying, 'semantic_runtime'::character varying])::text[]))),
    CONSTRAINT ck_rule_foundry_candidate_registry CHECK (((registry_kind)::text = ANY ((ARRAY['semgrep'::character varying, 'gitleaks'::character varying, 'osv'::character varying, 'ai_dataflow'::character varying])::text[]))),
    CONSTRAINT ck_rule_foundry_candidate_representability CHECK (((static_representable AND ((registry_kind)::text <> 'ai_dataflow'::text) AND (non_representable_reason IS NULL)) OR ((NOT static_representable) AND ((registry_kind)::text = 'ai_dataflow'::text) AND (length(non_representable_reason) > 0)))),
    CONSTRAINT ck_rule_foundry_candidate_status CHECK (((status)::text = ANY ((ARRAY['ai_dataflow'::character varying, 'pending_review'::character varying, 'rejected'::character varying, 'approved'::character varying, 'shadow'::character varying, 'promoted'::character varying, 'rolled_back'::character varying, 'expired'::character varying, 'review_required'::character varying])::text[])))
);

ALTER TABLE ONLY public.rule_foundry_candidates FORCE ROW LEVEL SECURITY;


--
-- Name: rule_foundry_deployments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rule_foundry_deployments (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    candidate_id uuid NOT NULL,
    version_id uuid NOT NULL,
    prior_version_id uuid,
    state character varying(24) NOT NULL,
    actor_user_id integer,
    shadow_started_at timestamp with time zone,
    review_due_at timestamp with time zone,
    promoted_at timestamp with time zone,
    ended_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_rule_foundry_deployment_state CHECK (((state)::text = ANY ((ARRAY['shadow'::character varying, 'promoted'::character varying, 'rolled_back'::character varying, 'superseded'::character varying, 'review_required'::character varying])::text[])))
);

ALTER TABLE ONLY public.rule_foundry_deployments FORCE ROW LEVEL SECURITY;


--
-- Name: rule_foundry_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rule_foundry_events (
    id bigint NOT NULL,
    tenant_id uuid NOT NULL,
    candidate_id uuid NOT NULL,
    action character varying(32) NOT NULL,
    actor_user_id integer,
    reason character varying(500) NOT NULL,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.rule_foundry_events FORCE ROW LEVEL SECURITY;


--
-- Name: rule_foundry_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.rule_foundry_events ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.rule_foundry_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: rule_foundry_gitleaks_candidates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rule_foundry_gitleaks_candidates (
    candidate_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    rule jsonb NOT NULL
);

ALTER TABLE ONLY public.rule_foundry_gitleaks_candidates FORCE ROW LEVEL SECURITY;


--
-- Name: rule_foundry_osv_candidates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rule_foundry_osv_candidates (
    candidate_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    advisory jsonb NOT NULL
);

ALTER TABLE ONLY public.rule_foundry_osv_candidates FORCE ROW LEVEL SECURITY;


--
-- Name: rule_foundry_semgrep_candidates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rule_foundry_semgrep_candidates (
    candidate_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    rule jsonb NOT NULL
);

ALTER TABLE ONLY public.rule_foundry_semgrep_candidates FORCE ROW LEVEL SECURITY;


--
-- Name: rule_foundry_shadow_observations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rule_foundry_shadow_observations (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    scan_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    eligible_files integer NOT NULL,
    unexpected_matches integer NOT NULL,
    evidence_digest character varying(64) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_rule_foundry_shadow_bounds CHECK (((eligible_files >= 0) AND (eligible_files <= 5000) AND (unexpected_matches >= 0) AND (unexpected_matches <= eligible_files)))
);

ALTER TABLE ONLY public.rule_foundry_shadow_observations FORCE ROW LEVEL SECURITY;


--
-- Name: rule_foundry_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rule_foundry_versions (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    candidate_id uuid NOT NULL,
    version integer NOT NULL,
    canonical_payload jsonb NOT NULL,
    payload_sha256 character varying(64) NOT NULL,
    signature text NOT NULL,
    signature_algorithm character varying(64) NOT NULL,
    signing_key_id character varying(512) NOT NULL,
    quality_metrics jsonb NOT NULL,
    reviewer_decision jsonb NOT NULL,
    reviewer_user_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_rule_foundry_version_positive CHECK ((version > 0))
);

ALTER TABLE ONLY public.rule_foundry_versions FORCE ROW LEVEL SECURITY;


--
-- Name: saml_subjects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.saml_subjects (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id integer NOT NULL,
    provider_id uuid NOT NULL,
    name_id character varying(512) NOT NULL,
    name_id_format character varying(128) NOT NULL,
    session_index character varying(256),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id uuid
);


--
-- Name: scan_artifacts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scan_artifacts (
    id uuid NOT NULL,
    scan_id uuid NOT NULL,
    artifact_type character varying(64) NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    payload jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    attempt_id uuid,
    evidence_id uuid
);

ALTER TABLE ONLY public.scan_artifacts FORCE ROW LEVEL SECURITY;


--
-- Name: scan_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scan_attempts (
    id uuid NOT NULL,
    scan_id uuid NOT NULL,
    tenant_id uuid DEFAULT '00000000-0000-0000-0000-000000000001'::uuid NOT NULL,
    sequence integer NOT NULL,
    trigger character varying(32) NOT NULL,
    status character varying(20) NOT NULL,
    parent_attempt_id uuid,
    actor_user_id integer,
    graph_thread_id character varying(255) NOT NULL,
    configuration_digest character varying(64),
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_scan_attempts_status CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'completed'::character varying, 'failed'::character varying, 'cancelled'::character varying, 'superseded'::character varying])::text[]))),
    CONSTRAINT ck_scan_attempts_trigger CHECK (((trigger)::text = ANY ((ARRAY['initial'::character varying, 'restart'::character varying, 'legacy_backfill'::character varying])::text[])))
);

ALTER TABLE ONLY public.scan_attempts FORCE ROW LEVEL SECURITY;


--
-- Name: scan_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scan_events (
    id bigint NOT NULL,
    scan_id uuid NOT NULL,
    stage_name character varying(100) NOT NULL,
    status character varying(20) NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    details jsonb,
    attempt_id uuid,
    schema_version integer DEFAULT 1 NOT NULL,
    activity_kind character varying(32) DEFAULT 'workflow'::character varying NOT NULL,
    CONSTRAINT ck_scan_events_activity_kind CHECK (((activity_kind)::text = ANY ((ARRAY['workflow'::character varying, 'scanner'::character varying, 'llm_call'::character varying, 'retry'::character varying, 'warning'::character varying, 'degradation'::character varying, 'decision'::character varying, 'cancellation'::character varying, 'terminal'::character varying])::text[]))),
    CONSTRAINT ck_scan_events_schema_version_positive CHECK ((schema_version > 0))
);

ALTER TABLE ONLY public.scan_events FORCE ROW LEVEL SECURITY;


--
-- Name: scan_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.scan_events ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.scan_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: scan_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scan_outbox (
    id uuid NOT NULL,
    scan_id uuid NOT NULL,
    queue_name character varying(255) NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    published_at timestamp with time zone,
    attempts integer DEFAULT 0 NOT NULL,
    idempotency_key character varying(255),
    attempt_id uuid
);

ALTER TABLE ONLY public.scan_outbox FORCE ROW LEVEL SECURITY;


--
-- Name: scan_tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scan_tasks (
    id uuid NOT NULL,
    scan_id uuid NOT NULL,
    task_type character varying(64) NOT NULL,
    task_key text NOT NULL,
    input_hash character varying(64) NOT NULL,
    prompt_hash character varying(64) NOT NULL,
    version_hash character varying(64) NOT NULL,
    input_payload jsonb NOT NULL,
    result_payload jsonb,
    status character varying(20) NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 3 NOT NULL,
    lease_owner character varying(255),
    lease_expires_at timestamp with time zone,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    attempt_id uuid,
    CONSTRAINT ck_scan_tasks_attempts_nonnegative CHECK ((attempts >= 0)),
    CONSTRAINT ck_scan_tasks_max_attempts_positive CHECK ((max_attempts > 0)),
    CONSTRAINT ck_scan_tasks_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'completed'::character varying, 'failed'::character varying, 'stale'::character varying, 'retryable'::character varying])::text[])))
);

ALTER TABLE ONLY public.scan_tasks FORCE ROW LEVEL SECURITY;


--
-- Name: scanner_coverage_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scanner_coverage_entries (
    id uuid NOT NULL,
    scan_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    scanner_name character varying(64) NOT NULL,
    input_path text NOT NULL,
    status character varying(20) NOT NULL,
    reason_code character varying(64),
    reason text,
    finding_count integer DEFAULT 0 NOT NULL,
    native_evidence_available boolean DEFAULT false NOT NULL,
    provenance_status character varying(20),
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_scanner_coverage_status CHECK (((status)::text = ANY ((ARRAY['planned'::character varying, 'completed'::character varying, 'clean'::character varying, 'skipped'::character varying, 'failed'::character varying, 'timeout'::character varying, 'unsupported'::character varying, 'truncated'::character varying])::text[])))
);

ALTER TABLE ONLY public.scanner_coverage_entries FORCE ROW LEVEL SECURITY;


--
-- Name: scanner_coverage_policy_decisions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scanner_coverage_policy_decisions (
    id uuid NOT NULL,
    scan_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    failing_states jsonb NOT NULL,
    matching_entry_ids jsonb NOT NULL,
    outcome character varying(16) NOT NULL,
    audit_reason text NOT NULL,
    actor_user_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_scanner_coverage_policy_outcome CHECK (((outcome)::text = ANY ((ARRAY['pass'::character varying, 'fail'::character varying, 'waived'::character varying])::text[])))
);

ALTER TABLE ONLY public.scanner_coverage_policy_decisions FORCE ROW LEVEL SECURITY;


--
-- Name: scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scans (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    user_id integer NOT NULL,
    parent_scan_id uuid,
    scan_type character varying(50) NOT NULL,
    status character varying(50) NOT NULL,
    cost_details jsonb,
    summary jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    frameworks jsonb,
    risk_score integer,
    repository_map jsonb,
    dependency_graph jsonb,
    context_bundles jsonb,
    reasoning_llm_config_id uuid,
    bom_cyclonedx jsonb,
    tenant_id uuid DEFAULT '00000000-0000-0000-0000-000000000001'::uuid NOT NULL,
    utility_llm_config_id uuid,
    file_profiles jsonb,
    stage_temperatures jsonb,
    cross_file_validation boolean DEFAULT false NOT NULL,
    disable_temperature boolean DEFAULT false NOT NULL,
    secondary_reasoning_llm_config_id uuid,
    source_type character varying(20),
    deep_vendor_scan boolean DEFAULT false NOT NULL,
    error_message text,
    current_attempt_id uuid,
    CONSTRAINT ck_scans_source_type CHECK (((source_type IS NULL) OR ((source_type)::text = ANY ((ARRAY['upload'::character varying, 'archive'::character varying, 'git'::character varying, 'paste'::character varying])::text[]))))
);

ALTER TABLE ONLY public.scans FORCE ROW LEVEL SECURITY;


--
-- Name: scim_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scim_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(128) NOT NULL,
    token_hash character varying(64) NOT NULL,
    scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    created_by_user_id integer,
    tenant_id uuid DEFAULT '00000000-0000-0000-0000-000000000001'::uuid NOT NULL
);

ALTER TABLE ONLY public.scim_tokens FORCE ROW LEVEL SECURITY;


--
-- Name: semgrep_rule_sources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.semgrep_rule_sources (
    id uuid NOT NULL,
    slug character varying(64) NOT NULL,
    display_name character varying(255) NOT NULL,
    description text NOT NULL,
    repo_url text NOT NULL,
    branch character varying(128) DEFAULT 'main'::character varying NOT NULL,
    subpath text,
    license_spdx character varying(64) NOT NULL,
    author character varying(255) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    auto_sync boolean DEFAULT false NOT NULL,
    sync_cron character varying(64) DEFAULT '0 3 * * 0'::character varying,
    last_synced_at timestamp with time zone,
    last_commit_sha character varying(40),
    last_sync_status character varying(16) DEFAULT 'never'::character varying NOT NULL,
    last_sync_error text,
    rule_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: semgrep_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.semgrep_rules (
    id uuid NOT NULL,
    source_id uuid NOT NULL,
    namespaced_id text NOT NULL,
    original_id text NOT NULL,
    relative_path text NOT NULL,
    languages text[] DEFAULT '{}'::text[] NOT NULL,
    severity character varying(16) DEFAULT 'WARNING'::character varying NOT NULL,
    category character varying(64),
    technology text[] DEFAULT '{}'::text[] NOT NULL,
    cwe text[] DEFAULT '{}'::text[] NOT NULL,
    owasp text[] DEFAULT '{}'::text[] NOT NULL,
    confidence character varying(16),
    likelihood character varying(16),
    impact character varying(16),
    message text DEFAULT ''::text NOT NULL,
    raw_yaml jsonb NOT NULL,
    content_hash character varying(64) NOT NULL,
    license_spdx character varying(64) NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: semgrep_sync_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.semgrep_sync_runs (
    id uuid NOT NULL,
    source_id uuid NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    status character varying(16) DEFAULT 'running'::character varying NOT NULL,
    commit_sha_before character varying(40),
    commit_sha_after character varying(40),
    rules_added integer DEFAULT 0 NOT NULL,
    rules_updated integer DEFAULT 0 NOT NULL,
    rules_removed integer DEFAULT 0 NOT NULL,
    rules_invalid integer DEFAULT 0 NOT NULL,
    error text,
    triggered_by character varying(64) DEFAULT 'manual'::character varying NOT NULL
);


--
-- Name: source_code_files; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.source_code_files (
    hash character varying(64) NOT NULL,
    content text NOT NULL,
    language character varying(50) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sso_providers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sso_providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(64) NOT NULL,
    display_name character varying(128) NOT NULL,
    protocol character varying(8) NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    config_encrypted bytea NOT NULL,
    allowed_email_domains jsonb,
    force_for_domains jsonb,
    jit_policy character varying(16) DEFAULT 'auto'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id uuid,
    CONSTRAINT ck_sso_providers_jit_policy CHECK (((jit_policy)::text = ANY ((ARRAY['auto'::character varying, 'approve'::character varying, 'deny'::character varying])::text[]))),
    CONSTRAINT ck_sso_providers_protocol CHECK (((protocol)::text = ANY ((ARRAY['oidc'::character varying, 'saml'::character varying])::text[])))
);


--
-- Name: system_configurations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_configurations (
    key character varying(255) NOT NULL,
    value jsonb NOT NULL,
    description text,
    is_secret boolean DEFAULT false NOT NULL,
    encrypted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    version integer DEFAULT 1 NOT NULL
);


--
-- Name: tenant_retention_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_retention_policies (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    data_class character varying(24) NOT NULL,
    retention_days integer NOT NULL,
    updated_by_user_id integer NOT NULL,
    reason text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_tenant_retention_policy_class CHECK (((data_class)::text = ANY ((ARRAY['transactional'::character varying, 'audit'::character varying, 'evidence'::character varying, 'llm'::character varying, 'vector'::character varying, 'logs'::character varying, 'backups'::character varying])::text[]))),
    CONSTRAINT ck_tenant_retention_policy_days CHECK (((retention_days >= 1) AND (retention_days <= 3650)))
);

ALTER TABLE ONLY public.tenant_retention_policies FORCE ROW LEVEL SECURITY;


--
-- Name: tenant_verified_domains; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_verified_domains (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    domain character varying(253) NOT NULL,
    verification_token_hash character varying(64) NOT NULL,
    status character varying(16) DEFAULT 'pending'::character varying NOT NULL,
    verified_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_tenant_verified_domains_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'verified'::character varying])::text[])))
);


--
-- Name: tenants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    slug character varying(64) NOT NULL,
    display_name character varying(128) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    session_concurrency_limit integer,
    session_concurrency_mode character varying(16) DEFAULT 'deny_new'::character varying NOT NULL,
    separation_of_duties_mode character varying(16) DEFAULT 'off'::character varying NOT NULL,
    CONSTRAINT ck_tenants_separation_of_duties_mode CHECK (((separation_of_duties_mode)::text = ANY ((ARRAY['off'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT ck_tenants_session_concurrency_limit CHECK (((session_concurrency_limit IS NULL) OR ((session_concurrency_limit >= 1) AND (session_concurrency_limit <= 100)))),
    CONSTRAINT ck_tenants_session_concurrency_mode CHECK (((session_concurrency_mode)::text = ANY ((ARRAY['deny_new'::character varying, 'revoke_oldest'::character varying])::text[])))
);


--
-- Name: usage_budget_allocations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usage_budget_allocations (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    reservation_id uuid NOT NULL,
    counter_id uuid NOT NULL,
    held_input_tokens bigint DEFAULT '0'::bigint NOT NULL,
    held_output_tokens bigint DEFAULT '0'::bigint NOT NULL,
    held_total_tokens bigint DEFAULT '0'::bigint NOT NULL,
    held_uncached_input_tokens bigint DEFAULT '0'::bigint NOT NULL,
    held_billable_tokens bigint DEFAULT '0'::bigint NOT NULL,
    held_usd numeric(30,12) DEFAULT '0'::numeric NOT NULL,
    held_provider_requests bigint DEFAULT '0'::bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_usage_budget_allocations_nonnegative CHECK (((held_input_tokens >= 0) AND (held_output_tokens >= 0) AND (held_total_tokens >= 0) AND (held_uncached_input_tokens >= 0) AND (held_billable_tokens >= 0) AND (held_usd >= (0)::numeric) AND (held_provider_requests >= 0)))
);

ALTER TABLE ONLY public.usage_budget_allocations FORCE ROW LEVEL SECURITY;


--
-- Name: usage_budget_counters; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usage_budget_counters (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    window_key character varying(512) NOT NULL,
    window_start timestamp with time zone NOT NULL,
    window_end timestamp with time zone NOT NULL,
    spent_input_tokens bigint DEFAULT '0'::bigint NOT NULL,
    spent_output_tokens bigint DEFAULT '0'::bigint NOT NULL,
    spent_total_tokens bigint DEFAULT '0'::bigint NOT NULL,
    spent_uncached_input_tokens bigint DEFAULT '0'::bigint NOT NULL,
    spent_billable_tokens bigint DEFAULT '0'::bigint NOT NULL,
    spent_usd numeric(30,12) DEFAULT '0'::numeric NOT NULL,
    spent_provider_requests bigint DEFAULT '0'::bigint NOT NULL,
    held_input_tokens bigint DEFAULT '0'::bigint NOT NULL,
    held_output_tokens bigint DEFAULT '0'::bigint NOT NULL,
    held_total_tokens bigint DEFAULT '0'::bigint NOT NULL,
    held_uncached_input_tokens bigint DEFAULT '0'::bigint NOT NULL,
    held_billable_tokens bigint DEFAULT '0'::bigint NOT NULL,
    held_usd numeric(30,12) DEFAULT '0'::numeric NOT NULL,
    held_provider_requests bigint DEFAULT '0'::bigint NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_usage_budget_counters_interval CHECK ((window_end > window_start)),
    CONSTRAINT ck_usage_budget_counters_nonnegative CHECK (((spent_input_tokens >= 0) AND (spent_output_tokens >= 0) AND (spent_total_tokens >= 0) AND (spent_uncached_input_tokens >= 0) AND (spent_billable_tokens >= 0) AND (spent_usd >= (0)::numeric) AND (spent_provider_requests >= 0) AND (held_input_tokens >= 0) AND (held_output_tokens >= 0) AND (held_total_tokens >= 0) AND (held_uncached_input_tokens >= 0) AND (held_billable_tokens >= 0) AND (held_usd >= (0)::numeric) AND (held_provider_requests >= 0)))
);

ALTER TABLE ONLY public.usage_budget_counters FORCE ROW LEVEL SECURITY;


--
-- Name: usage_budget_notification_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usage_budget_notification_outbox (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    threshold_event_id uuid NOT NULL,
    recipient_user_id integer NOT NULL,
    state character varying(16) DEFAULT 'pending'::character varying NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    published_at timestamp with time zone,
    error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_usage_budget_notification_outbox_attempts CHECK ((attempts >= 0)),
    CONSTRAINT ck_usage_budget_notification_outbox_state CHECK (((state)::text = ANY ((ARRAY['pending'::character varying, 'published'::character varying, 'failed'::character varying])::text[])))
);

ALTER TABLE ONLY public.usage_budget_notification_outbox FORCE ROW LEVEL SECURITY;


--
-- Name: usage_budget_overrides; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usage_budget_overrides (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    window_key character varying(512) NOT NULL,
    allowance_input_tokens bigint DEFAULT '0'::bigint NOT NULL,
    allowance_output_tokens bigint DEFAULT '0'::bigint NOT NULL,
    allowance_total_tokens bigint DEFAULT '0'::bigint NOT NULL,
    allowance_uncached_input_tokens bigint DEFAULT '0'::bigint NOT NULL,
    allowance_billable_tokens bigint DEFAULT '0'::bigint NOT NULL,
    allowance_usd numeric(30,12) DEFAULT '0'::numeric NOT NULL,
    allowance_provider_requests bigint DEFAULT '0'::bigint NOT NULL,
    reason text NOT NULL,
    created_by_user_id integer NOT NULL,
    effective_from timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_usage_budget_overrides_interval CHECK ((expires_at > effective_from)),
    CONSTRAINT ck_usage_budget_overrides_nonnegative CHECK (((allowance_input_tokens >= 0) AND (allowance_output_tokens >= 0) AND (allowance_total_tokens >= 0) AND (allowance_uncached_input_tokens >= 0) AND (allowance_billable_tokens >= 0) AND (allowance_usd >= (0)::numeric) AND (allowance_provider_requests >= 0)))
);

ALTER TABLE ONLY public.usage_budget_overrides FORCE ROW LEVEL SECURITY;


--
-- Name: usage_budget_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usage_budget_policies (
    id uuid NOT NULL,
    logical_policy_id uuid NOT NULL,
    version integer NOT NULL,
    tenant_id uuid NOT NULL,
    scope_kind character varying(16) NOT NULL,
    target_group_id uuid,
    target_user_id integer,
    window_kind character varying(16) NOT NULL,
    llm_config_id uuid,
    stage character varying(100),
    cap_input_tokens bigint,
    cap_output_tokens bigint,
    cap_total_tokens bigint,
    cap_uncached_input_tokens bigint,
    cap_billable_tokens bigint,
    cap_usd numeric(30,12),
    cap_provider_requests bigint,
    soft_threshold_low integer DEFAULT 80 NOT NULL,
    soft_threshold_high integer DEFAULT 95 NOT NULL,
    unknown_price_action character varying(16) DEFAULT 'deny'::character varying NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    effective_from timestamp with time zone NOT NULL,
    effective_to timestamp with time zone,
    reason text NOT NULL,
    created_by_user_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_usage_budget_policies_caps_nonnegative CHECK (((cap_input_tokens IS NULL) OR ((cap_input_tokens >= 0) AND (cap_output_tokens IS NULL)) OR ((cap_output_tokens >= 0) AND (cap_total_tokens IS NULL)) OR ((cap_total_tokens >= 0) AND (cap_uncached_input_tokens IS NULL)) OR ((cap_uncached_input_tokens >= 0) AND (cap_billable_tokens IS NULL)) OR ((cap_billable_tokens >= 0) AND (cap_usd IS NULL)) OR ((cap_usd >= (0)::numeric) AND (cap_provider_requests IS NULL)) OR (cap_provider_requests >= 0))),
    CONSTRAINT ck_usage_budget_policies_has_cap CHECK (((cap_input_tokens IS NOT NULL) OR (cap_output_tokens IS NOT NULL) OR (cap_total_tokens IS NOT NULL) OR (cap_uncached_input_tokens IS NOT NULL) OR (cap_billable_tokens IS NOT NULL) OR (cap_usd IS NOT NULL) OR (cap_provider_requests IS NOT NULL))),
    CONSTRAINT ck_usage_budget_policies_interval CHECK (((effective_to IS NULL) OR (effective_to > effective_from))),
    CONSTRAINT ck_usage_budget_policies_scope_kind CHECK (((scope_kind)::text = ANY ((ARRAY['tenant'::character varying, 'group'::character varying, 'user'::character varying])::text[]))),
    CONSTRAINT ck_usage_budget_policies_scope_target CHECK (((((scope_kind)::text = 'tenant'::text) AND (target_group_id IS NULL) AND (target_user_id IS NULL)) OR (((scope_kind)::text = 'group'::text) AND (target_group_id IS NOT NULL) AND (target_user_id IS NULL)) OR (((scope_kind)::text = 'user'::text) AND (target_group_id IS NULL) AND (target_user_id IS NOT NULL)))),
    CONSTRAINT ck_usage_budget_policies_thresholds CHECK (((soft_threshold_low > 0) AND (soft_threshold_low < soft_threshold_high) AND (soft_threshold_high < 100))),
    CONSTRAINT ck_usage_budget_policies_unknown_price_action CHECK (((unknown_price_action)::text = ANY ((ARRAY['deny'::character varying, 'token_only'::character varying])::text[]))),
    CONSTRAINT ck_usage_budget_policies_window_kind CHECK (((window_kind)::text = ANY ((ARRAY['request'::character varying, 'scan'::character varying, 'day'::character varying, 'month'::character varying])::text[])))
);

ALTER TABLE ONLY public.usage_budget_policies FORCE ROW LEVEL SECURITY;


--
-- Name: usage_budget_reservations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usage_budget_reservations (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    idempotency_key character varying(512) NOT NULL,
    operation_kind character varying(32) NOT NULL,
    actor_user_id integer,
    group_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    request_key character varying(512) NOT NULL,
    scan_attempt_id uuid,
    llm_config_id uuid,
    stage character varying(100) NOT NULL,
    parent_reservation_id uuid,
    state character varying(20) DEFAULT 'held'::character varying NOT NULL,
    estimated_input_tokens bigint DEFAULT '0'::bigint NOT NULL,
    estimated_output_tokens bigint DEFAULT '0'::bigint NOT NULL,
    estimated_total_tokens bigint DEFAULT '0'::bigint NOT NULL,
    estimated_uncached_input_tokens bigint DEFAULT '0'::bigint NOT NULL,
    estimated_billable_tokens bigint DEFAULT '0'::bigint NOT NULL,
    estimated_usd numeric(30,12) DEFAULT '0'::numeric NOT NULL,
    estimated_provider_requests bigint DEFAULT '0'::bigint NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    finalized_at timestamp with time zone,
    release_reason character varying(100),
    CONSTRAINT ck_usage_budget_reservations_nonnegative CHECK (((estimated_input_tokens >= 0) AND (estimated_output_tokens >= 0) AND (estimated_total_tokens >= 0) AND (estimated_uncached_input_tokens >= 0) AND (estimated_billable_tokens >= 0) AND (estimated_usd >= (0)::numeric) AND (estimated_provider_requests >= 0))),
    CONSTRAINT ck_usage_budget_reservations_state CHECK (((state)::text = ANY ((ARRAY['held'::character varying, 'settled'::character varying, 'released'::character varying, 'expired'::character varying, 'accounting_unknown'::character varying])::text[])))
);

ALTER TABLE ONLY public.usage_budget_reservations FORCE ROW LEVEL SECURITY;


--
-- Name: usage_budget_settlements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usage_budget_settlements (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    reservation_id uuid NOT NULL,
    usage_event_id uuid NOT NULL,
    actual_input_tokens bigint DEFAULT '0'::bigint NOT NULL,
    actual_output_tokens bigint DEFAULT '0'::bigint NOT NULL,
    actual_total_tokens bigint DEFAULT '0'::bigint NOT NULL,
    actual_uncached_input_tokens bigint DEFAULT '0'::bigint NOT NULL,
    actual_billable_tokens bigint DEFAULT '0'::bigint NOT NULL,
    actual_usd numeric(30,12) DEFAULT '0'::numeric NOT NULL,
    actual_provider_requests bigint DEFAULT '0'::bigint NOT NULL,
    overrun jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_usage_budget_settlements_nonnegative CHECK (((actual_input_tokens >= 0) AND (actual_output_tokens >= 0) AND (actual_total_tokens >= 0) AND (actual_uncached_input_tokens >= 0) AND (actual_billable_tokens >= 0) AND (actual_usd >= (0)::numeric) AND (actual_provider_requests >= 0)))
);

ALTER TABLE ONLY public.usage_budget_settlements FORCE ROW LEVEL SECURITY;


--
-- Name: usage_budget_threshold_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usage_budget_threshold_events (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    counter_id uuid NOT NULL,
    dimension character varying(40) NOT NULL,
    threshold_percent integer NOT NULL,
    observed numeric(30,12) NOT NULL,
    effective_cap numeric(30,12) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_usage_budget_threshold_events_percent CHECK (((threshold_percent > 0) AND (threshold_percent < 100)))
);

ALTER TABLE ONLY public.usage_budget_threshold_events FORCE ROW LEVEL SECURITY;


--
-- Name: user; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public."user" (
    id integer NOT NULL,
    email character varying(320) NOT NULL,
    hashed_password character varying(1024) NOT NULL,
    is_active boolean NOT NULL,
    is_superuser boolean NOT NULL,
    is_verified boolean NOT NULL,
    tenant_id uuid DEFAULT '00000000-0000-0000-0000-000000000001'::uuid NOT NULL,
    preferences jsonb
);


--
-- Name: user_group_memberships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_group_memberships (
    group_id uuid NOT NULL,
    user_id integer NOT NULL,
    role character varying(16) DEFAULT 'member'::character varying NOT NULL,
    joined_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.user_group_memberships FORCE ROW LEVEL SECURITY;


--
-- Name: user_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_groups (
    id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    created_by integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    tenant_id uuid DEFAULT '00000000-0000-0000-0000-000000000001'::uuid NOT NULL
);

ALTER TABLE ONLY public.user_groups FORCE ROW LEVEL SECURITY;


--
-- Name: user_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_id_seq OWNED BY public."user".id;


--
-- Name: webauthn_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webauthn_credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id integer NOT NULL,
    credential_id bytea NOT NULL,
    public_key bytea NOT NULL,
    sign_count integer DEFAULT 0 NOT NULL,
    transports jsonb,
    friendly_name character varying(128) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone
);


--
-- Name: user id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public."user" ALTER COLUMN id SET DEFAULT nextval('public.user_id_seq'::regclass);


--
-- Name: agents agents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_pkey PRIMARY KEY (id);


--
-- Name: approval_gates approval_gates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approval_gates
    ADD CONSTRAINT approval_gates_pkey PRIMARY KEY (gate_id);


--
-- Name: auth_audit_events auth_audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_audit_events
    ADD CONSTRAINT auth_audit_events_pkey PRIMARY KEY (id);


--
-- Name: auth_sessions auth_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT auth_sessions_pkey PRIMARY KEY (id);


--
-- Name: authorization_action_requests authorization_action_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_action_requests
    ADD CONSTRAINT authorization_action_requests_pkey PRIMARY KEY (id);


--
-- Name: authorization_audit_events authorization_audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_audit_events
    ADD CONSTRAINT authorization_audit_events_pkey PRIMARY KEY (id);


--
-- Name: chat_messages chat_messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_messages
    ADD CONSTRAINT chat_messages_pkey PRIMARY KEY (id);


--
-- Name: chat_sessions chat_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sessions
    ADD CONSTRAINT chat_sessions_pkey PRIMARY KEY (id);


--
-- Name: code_snapshots code_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.code_snapshots
    ADD CONSTRAINT code_snapshots_pkey PRIMARY KEY (id);


--
-- Name: cwe_details cwe_details_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cwe_details
    ADD CONSTRAINT cwe_details_pkey PRIMARY KEY (id);


--
-- Name: cwe_owasp_mappings cwe_owasp_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cwe_owasp_mappings
    ADD CONSTRAINT cwe_owasp_mappings_pkey PRIMARY KEY (cwe_id);


--
-- Name: evidence_deletion_outbox evidence_deletion_outbox_evidence_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_deletion_outbox
    ADD CONSTRAINT evidence_deletion_outbox_evidence_id_key UNIQUE (evidence_id);


--
-- Name: evidence_deletion_outbox evidence_deletion_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_deletion_outbox
    ADD CONSTRAINT evidence_deletion_outbox_pkey PRIMARY KEY (id);


--
-- Name: evidence_governance_events evidence_governance_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_governance_events
    ADD CONSTRAINT evidence_governance_events_pkey PRIMARY KEY (id);


--
-- Name: evidence_manifests evidence_manifests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_manifests
    ADD CONSTRAINT evidence_manifests_pkey PRIMARY KEY (id);


--
-- Name: evidence_objects evidence_objects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_objects
    ADD CONSTRAINT evidence_objects_pkey PRIMARY KEY (id);


--
-- Name: federation_replay_markers federation_replay_markers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_replay_markers
    ADD CONSTRAINT federation_replay_markers_pkey PRIMARY KEY (id);


--
-- Name: finding_disposition_events finding_disposition_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_disposition_events
    ADD CONSTRAINT finding_disposition_events_pkey PRIMARY KEY (id);


--
-- Name: finding_fix_candidates finding_fix_candidates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_fix_candidates
    ADD CONSTRAINT finding_fix_candidates_pkey PRIMARY KEY (candidate_id);


--
-- Name: finding_lineage_records finding_lineage_records_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_lineage_records
    ADD CONSTRAINT finding_lineage_records_pkey PRIMARY KEY (id);


--
-- Name: finding_policy_evaluations finding_policy_evaluations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_policy_evaluations
    ADD CONSTRAINT finding_policy_evaluations_pkey PRIMARY KEY (id);


--
-- Name: finding_policy_versions finding_policy_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_policy_versions
    ADD CONSTRAINT finding_policy_versions_pkey PRIMARY KEY (id);


--
-- Name: finding_waiver_events finding_waiver_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_waiver_events
    ADD CONSTRAINT finding_waiver_events_pkey PRIMARY KEY (id);


--
-- Name: finding_waivers finding_waivers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_waivers
    ADD CONSTRAINT finding_waivers_pkey PRIMARY KEY (id);


--
-- Name: findings findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (id);


--
-- Name: framework_agent_mappings framework_agent_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.framework_agent_mappings
    ADD CONSTRAINT framework_agent_mappings_pkey PRIMARY KEY (framework_id, agent_id);


--
-- Name: frameworks frameworks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.frameworks
    ADD CONSTRAINT frameworks_pkey PRIMARY KEY (id);


--
-- Name: governance_legal_holds governance_legal_holds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_legal_holds
    ADD CONSTRAINT governance_legal_holds_pkey PRIMARY KEY (id);


--
-- Name: governance_operations governance_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_operations
    ADD CONSTRAINT governance_operations_pkey PRIMARY KEY (id);


--
-- Name: governance_store_actions governance_store_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_store_actions
    ADD CONSTRAINT governance_store_actions_pkey PRIMARY KEY (id);


--
-- Name: integration_delivery_audit integration_delivery_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_delivery_audit
    ADD CONSTRAINT integration_delivery_audit_pkey PRIMARY KEY (id);


--
-- Name: integration_finding_tickets integration_finding_tickets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_finding_tickets
    ADD CONSTRAINT integration_finding_tickets_pkey PRIMARY KEY (id);


--
-- Name: integration_grants integration_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_grants
    ADD CONSTRAINT integration_grants_pkey PRIMARY KEY (id);


--
-- Name: integration_inbound_receipts integration_inbound_receipts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_inbound_receipts
    ADD CONSTRAINT integration_inbound_receipts_pkey PRIMARY KEY (id);


--
-- Name: integration_outbox integration_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_outbox
    ADD CONSTRAINT integration_outbox_pkey PRIMARY KEY (id);


--
-- Name: integration_service_principals integration_service_principals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_service_principals
    ADD CONSTRAINT integration_service_principals_pkey PRIMARY KEY (id);


--
-- Name: integration_source_submissions integration_source_submissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_source_submissions
    ADD CONSTRAINT integration_source_submissions_pkey PRIMARY KEY (id);


--
-- Name: integration_ticket_history integration_ticket_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_ticket_history
    ADD CONSTRAINT integration_ticket_history_pkey PRIMARY KEY (id);


--
-- Name: llm_call_reservations llm_call_reservations_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_call_reservations
    ADD CONSTRAINT llm_call_reservations_idempotency_key_key UNIQUE (idempotency_key);


--
-- Name: llm_call_reservations llm_call_reservations_owner_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_call_reservations
    ADD CONSTRAINT llm_call_reservations_owner_token_key UNIQUE (owner_token);


--
-- Name: llm_call_reservations llm_call_reservations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_call_reservations
    ADD CONSTRAINT llm_call_reservations_pkey PRIMARY KEY (id);


--
-- Name: llm_call_reservations llm_call_reservations_usage_event_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_call_reservations
    ADD CONSTRAINT llm_call_reservations_usage_event_id_key UNIQUE (usage_event_id);


--
-- Name: llm_configurations llm_configurations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_configurations
    ADD CONSTRAINT llm_configurations_pkey PRIMARY KEY (id);


--
-- Name: llm_interactions llm_interactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_interactions
    ADD CONSTRAINT llm_interactions_pkey PRIMARY KEY (id);


--
-- Name: llm_price_overrides llm_price_overrides_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_price_overrides
    ADD CONSTRAINT llm_price_overrides_pkey PRIMARY KEY (id);


--
-- Name: llm_usage_events llm_usage_events_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage_events
    ADD CONSTRAINT llm_usage_events_idempotency_key_key UNIQUE (idempotency_key);


--
-- Name: llm_usage_events llm_usage_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage_events
    ADD CONSTRAINT llm_usage_events_pkey PRIMARY KEY (id);


--
-- Name: llm_usage_line_items llm_usage_line_items_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage_line_items
    ADD CONSTRAINT llm_usage_line_items_pkey PRIMARY KEY (id);


--
-- Name: llm_usage_requests llm_usage_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage_requests
    ADD CONSTRAINT llm_usage_requests_pkey PRIMARY KEY (id);


--
-- Name: oauth_accounts oauth_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_accounts
    ADD CONSTRAINT oauth_accounts_pkey PRIMARY KEY (id);


--
-- Name: offline_bundle_deployments offline_bundle_deployments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.offline_bundle_deployments
    ADD CONSTRAINT offline_bundle_deployments_pkey PRIMARY KEY (id);


--
-- Name: projects projects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_pkey PRIMARY KEY (id);


--
-- Name: prompt_templates prompt_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.prompt_templates
    ADD CONSTRAINT prompt_templates_pkey PRIMARY KEY (id);


--
-- Name: provider_billing_connectors provider_billing_connectors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_billing_connectors
    ADD CONSTRAINT provider_billing_connectors_pkey PRIMARY KEY (id);


--
-- Name: provider_reconciliation_adjustments provider_reconciliation_adjustments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_reconciliation_adjustments
    ADD CONSTRAINT provider_reconciliation_adjustments_pkey PRIMARY KEY (id);


--
-- Name: provider_reconciliation_alert_outbox provider_reconciliation_alert_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_reconciliation_alert_outbox
    ADD CONSTRAINT provider_reconciliation_alert_outbox_pkey PRIMARY KEY (id);


--
-- Name: provider_reconciliation_alert_outbox provider_reconciliation_alert_outbox_run_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_reconciliation_alert_outbox
    ADD CONSTRAINT provider_reconciliation_alert_outbox_run_id_key UNIQUE (run_id);


--
-- Name: provider_reconciliation_evidence provider_reconciliation_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_reconciliation_evidence
    ADD CONSTRAINT provider_reconciliation_evidence_pkey PRIMARY KEY (id);


--
-- Name: provider_reconciliation_runs provider_reconciliation_runs_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_reconciliation_runs
    ADD CONSTRAINT provider_reconciliation_runs_idempotency_key_key UNIQUE (idempotency_key);


--
-- Name: provider_reconciliation_runs provider_reconciliation_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_reconciliation_runs
    ADD CONSTRAINT provider_reconciliation_runs_pkey PRIMARY KEY (id);


--
-- Name: push_subscriptions push_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_subscriptions
    ADD CONSTRAINT push_subscriptions_pkey PRIMARY KEY (id);


--
-- Name: rag_preprocessing_jobs rag_preprocessing_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rag_preprocessing_jobs
    ADD CONSTRAINT rag_preprocessing_jobs_pkey PRIMARY KEY (id);


--
-- Name: role_assignments role_assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_assignments
    ADD CONSTRAINT role_assignments_pkey PRIMARY KEY (id);


--
-- Name: rule_foundry_candidates rule_foundry_candidates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_candidates
    ADD CONSTRAINT rule_foundry_candidates_pkey PRIMARY KEY (id);


--
-- Name: rule_foundry_deployments rule_foundry_deployments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_deployments
    ADD CONSTRAINT rule_foundry_deployments_pkey PRIMARY KEY (id);


--
-- Name: rule_foundry_events rule_foundry_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_events
    ADD CONSTRAINT rule_foundry_events_pkey PRIMARY KEY (id);


--
-- Name: rule_foundry_gitleaks_candidates rule_foundry_gitleaks_candidates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_gitleaks_candidates
    ADD CONSTRAINT rule_foundry_gitleaks_candidates_pkey PRIMARY KEY (candidate_id);


--
-- Name: rule_foundry_osv_candidates rule_foundry_osv_candidates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_osv_candidates
    ADD CONSTRAINT rule_foundry_osv_candidates_pkey PRIMARY KEY (candidate_id);


--
-- Name: rule_foundry_semgrep_candidates rule_foundry_semgrep_candidates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_semgrep_candidates
    ADD CONSTRAINT rule_foundry_semgrep_candidates_pkey PRIMARY KEY (candidate_id);


--
-- Name: rule_foundry_shadow_observations rule_foundry_shadow_observations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_shadow_observations
    ADD CONSTRAINT rule_foundry_shadow_observations_pkey PRIMARY KEY (id);


--
-- Name: rule_foundry_versions rule_foundry_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_versions
    ADD CONSTRAINT rule_foundry_versions_pkey PRIMARY KEY (id);


--
-- Name: saml_subjects saml_subjects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saml_subjects
    ADD CONSTRAINT saml_subjects_pkey PRIMARY KEY (id);


--
-- Name: scan_artifacts scan_artifacts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_artifacts
    ADD CONSTRAINT scan_artifacts_pkey PRIMARY KEY (id);


--
-- Name: scan_attempts scan_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_attempts
    ADD CONSTRAINT scan_attempts_pkey PRIMARY KEY (id);


--
-- Name: scan_events scan_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_events
    ADD CONSTRAINT scan_events_pkey PRIMARY KEY (id);


--
-- Name: scan_outbox scan_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_outbox
    ADD CONSTRAINT scan_outbox_pkey PRIMARY KEY (id);


--
-- Name: scan_tasks scan_tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_tasks
    ADD CONSTRAINT scan_tasks_pkey PRIMARY KEY (id);


--
-- Name: scanner_coverage_entries scanner_coverage_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scanner_coverage_entries
    ADD CONSTRAINT scanner_coverage_entries_pkey PRIMARY KEY (id);


--
-- Name: scanner_coverage_policy_decisions scanner_coverage_policy_decisions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scanner_coverage_policy_decisions
    ADD CONSTRAINT scanner_coverage_policy_decisions_pkey PRIMARY KEY (id);


--
-- Name: scans scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_pkey PRIMARY KEY (id);


--
-- Name: scim_tokens scim_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scim_tokens
    ADD CONSTRAINT scim_tokens_pkey PRIMARY KEY (id);


--
-- Name: semgrep_rule_sources semgrep_rule_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.semgrep_rule_sources
    ADD CONSTRAINT semgrep_rule_sources_pkey PRIMARY KEY (id);


--
-- Name: semgrep_rules semgrep_rules_namespaced_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.semgrep_rules
    ADD CONSTRAINT semgrep_rules_namespaced_id_key UNIQUE (namespaced_id);


--
-- Name: semgrep_rules semgrep_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.semgrep_rules
    ADD CONSTRAINT semgrep_rules_pkey PRIMARY KEY (id);


--
-- Name: semgrep_sync_runs semgrep_sync_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.semgrep_sync_runs
    ADD CONSTRAINT semgrep_sync_runs_pkey PRIMARY KEY (id);


--
-- Name: source_code_files source_code_files_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_code_files
    ADD CONSTRAINT source_code_files_pkey PRIMARY KEY (hash);


--
-- Name: sso_providers sso_providers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_providers
    ADD CONSTRAINT sso_providers_pkey PRIMARY KEY (id);


--
-- Name: system_configurations system_configurations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_configurations
    ADD CONSTRAINT system_configurations_pkey PRIMARY KEY (key);


--
-- Name: tenant_retention_policies tenant_retention_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_retention_policies
    ADD CONSTRAINT tenant_retention_policies_pkey PRIMARY KEY (id);


--
-- Name: tenant_verified_domains tenant_verified_domains_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_verified_domains
    ADD CONSTRAINT tenant_verified_domains_pkey PRIMARY KEY (id);


--
-- Name: tenants tenants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);


--
-- Name: approval_gates uq_approval_gates_scan_decision_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approval_gates
    ADD CONSTRAINT uq_approval_gates_scan_decision_key UNIQUE (scan_id, decision_idempotency_key);


--
-- Name: approval_gates uq_approval_gates_scan_sequence; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approval_gates
    ADD CONSTRAINT uq_approval_gates_scan_sequence UNIQUE (scan_id, sequence);


--
-- Name: auth_sessions uq_auth_sessions_credential_secret_hash; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT uq_auth_sessions_credential_secret_hash UNIQUE (credential_secret_hash);


--
-- Name: authorization_action_requests uq_authorization_action_requests_tenant_idempotency; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_action_requests
    ADD CONSTRAINT uq_authorization_action_requests_tenant_idempotency UNIQUE (tenant_id, idempotency_key);


--
-- Name: evidence_manifests uq_evidence_manifest_digest; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_manifests
    ADD CONSTRAINT uq_evidence_manifest_digest UNIQUE (attempt_id, manifest_sha256);


--
-- Name: evidence_manifests uq_evidence_manifest_generation; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_manifests
    ADD CONSTRAINT uq_evidence_manifest_generation UNIQUE (attempt_id, generation);


--
-- Name: evidence_objects uq_evidence_object_version; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_objects
    ADD CONSTRAINT uq_evidence_object_version UNIQUE (object_key, object_version);


--
-- Name: evidence_objects uq_evidence_objects_attempt_type_version; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_objects
    ADD CONSTRAINT uq_evidence_objects_attempt_type_version UNIQUE (attempt_id, artifact_type, version);


--
-- Name: evidence_objects uq_evidence_objects_legacy_artifact_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_objects
    ADD CONSTRAINT uq_evidence_objects_legacy_artifact_id UNIQUE (legacy_artifact_id);


--
-- Name: federation_replay_markers uq_federation_replay_provider_kind_message; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_replay_markers
    ADD CONSTRAINT uq_federation_replay_provider_kind_message UNIQUE (provider_id, kind, message_hash);


--
-- Name: finding_lineage_records uq_finding_lineage_attempt_fingerprint_state_site; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_lineage_records
    ADD CONSTRAINT uq_finding_lineage_attempt_fingerprint_state_site UNIQUE (scan_id, attempt_id, fingerprint, baseline_state, site_identity);


--
-- Name: finding_policy_versions uq_finding_policy_tenant_version; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_policy_versions
    ADD CONSTRAINT uq_finding_policy_tenant_version UNIQUE (tenant_id, version);


--
-- Name: finding_waiver_events uq_finding_waiver_event_action; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_waiver_events
    ADD CONSTRAINT uq_finding_waiver_event_action UNIQUE (waiver_id, action);


--
-- Name: governance_operations uq_governance_operation_idempotency; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_operations
    ADD CONSTRAINT uq_governance_operation_idempotency UNIQUE (tenant_id, idempotency_key);


--
-- Name: governance_store_actions uq_governance_store_action_operation_store; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_store_actions
    ADD CONSTRAINT uq_governance_store_action_operation_store UNIQUE (operation_id, store);


--
-- Name: integration_outbox uq_integration_outbox_idempotency; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_outbox
    ADD CONSTRAINT uq_integration_outbox_idempotency UNIQUE (tenant_id, idempotency_key);


--
-- Name: integration_outbox uq_integration_outbox_source_event; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_outbox
    ADD CONSTRAINT uq_integration_outbox_source_event UNIQUE (principal_id, source_event_key);


--
-- Name: integration_service_principals uq_integration_principal_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_service_principals
    ADD CONSTRAINT uq_integration_principal_name UNIQUE (tenant_id, kind, display_name);


--
-- Name: integration_inbound_receipts uq_integration_receipt_nonce; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_inbound_receipts
    ADD CONSTRAINT uq_integration_receipt_nonce UNIQUE (principal_id, nonce);


--
-- Name: integration_inbound_receipts uq_integration_receipt_source_event; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_inbound_receipts
    ADD CONSTRAINT uq_integration_receipt_source_event UNIQUE (principal_id, source_event_id);


--
-- Name: integration_source_submissions uq_integration_source_submission_scan; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_source_submissions
    ADD CONSTRAINT uq_integration_source_submission_scan UNIQUE (scan_id);


--
-- Name: integration_finding_tickets uq_integration_ticket_canonical_root; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_finding_tickets
    ADD CONSTRAINT uq_integration_ticket_canonical_root UNIQUE (principal_id, canonical_root_id);


--
-- Name: llm_interactions uq_llm_interactions_usage_event_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_interactions
    ADD CONSTRAINT uq_llm_interactions_usage_event_id UNIQUE (usage_event_id);


--
-- Name: llm_price_overrides uq_llm_price_override_version; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_price_overrides
    ADD CONSTRAINT uq_llm_price_override_version UNIQUE (llm_config_id, effective_from);


--
-- Name: llm_usage_line_items uq_llm_usage_line_item_index; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage_line_items
    ADD CONSTRAINT uq_llm_usage_line_item_index UNIQUE (usage_request_id, line_index);


--
-- Name: llm_usage_requests uq_llm_usage_request_index; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage_requests
    ADD CONSTRAINT uq_llm_usage_request_index UNIQUE (usage_event_id, request_index);


--
-- Name: oauth_accounts uq_oauth_accounts_provider_account; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_accounts
    ADD CONSTRAINT uq_oauth_accounts_provider_account UNIQUE (provider_id, account_id);


--
-- Name: offline_bundle_deployments uq_offline_bundle_deployment_sequence; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.offline_bundle_deployments
    ADD CONSTRAINT uq_offline_bundle_deployment_sequence UNIQUE (bundle_sha256, sequence);


--
-- Name: projects uq_projects_user_id_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT uq_projects_user_id_name UNIQUE (user_id, name);


--
-- Name: prompt_templates uq_prompt_templates_agent_type_variant; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.prompt_templates
    ADD CONSTRAINT uq_prompt_templates_agent_type_variant UNIQUE (agent_name, template_type, variant);


--
-- Name: provider_billing_connectors uq_provider_billing_connector_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_billing_connectors
    ADD CONSTRAINT uq_provider_billing_connector_name UNIQUE (tenant_id, provider, display_name);


--
-- Name: provider_reconciliation_evidence uq_provider_reconciliation_evidence_dimension; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_reconciliation_evidence
    ADD CONSTRAINT uq_provider_reconciliation_evidence_dimension UNIQUE (run_id, dimension_key);


--
-- Name: push_subscriptions uq_push_subscriptions_endpoint; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_subscriptions
    ADD CONSTRAINT uq_push_subscriptions_endpoint UNIQUE (endpoint);


--
-- Name: rule_foundry_candidates uq_rule_foundry_candidate_identity; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_candidates
    ADD CONSTRAINT uq_rule_foundry_candidate_identity UNIQUE (tenant_id, registry_kind, stable_identity);


--
-- Name: rule_foundry_versions uq_rule_foundry_payload_hash; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_versions
    ADD CONSTRAINT uq_rule_foundry_payload_hash UNIQUE (tenant_id, payload_sha256);


--
-- Name: rule_foundry_shadow_observations uq_rule_foundry_shadow_attempt; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_shadow_observations
    ADD CONSTRAINT uq_rule_foundry_shadow_attempt UNIQUE (deployment_id, attempt_id);


--
-- Name: rule_foundry_versions uq_rule_foundry_version; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_versions
    ADD CONSTRAINT uq_rule_foundry_version UNIQUE (candidate_id, version);


--
-- Name: saml_subjects uq_saml_subjects_provider_name_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saml_subjects
    ADD CONSTRAINT uq_saml_subjects_provider_name_id UNIQUE (provider_id, name_id);


--
-- Name: scan_artifacts uq_scan_artifacts_evidence_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_artifacts
    ADD CONSTRAINT uq_scan_artifacts_evidence_id UNIQUE (evidence_id);


--
-- Name: scan_artifacts uq_scan_artifacts_type_version; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_artifacts
    ADD CONSTRAINT uq_scan_artifacts_type_version UNIQUE (scan_id, artifact_type, version);


--
-- Name: scan_attempts uq_scan_attempts_sequence; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_attempts
    ADD CONSTRAINT uq_scan_attempts_sequence UNIQUE (scan_id, sequence);


--
-- Name: scan_outbox uq_scan_outbox_idempotency_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_outbox
    ADD CONSTRAINT uq_scan_outbox_idempotency_key UNIQUE (idempotency_key);


--
-- Name: scan_tasks uq_scan_tasks_scan_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_tasks
    ADD CONSTRAINT uq_scan_tasks_scan_type_key UNIQUE (scan_id, task_type, task_key);


--
-- Name: scanner_coverage_entries uq_scanner_coverage_attempt_scanner_input; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scanner_coverage_entries
    ADD CONSTRAINT uq_scanner_coverage_attempt_scanner_input UNIQUE (attempt_id, scanner_name, input_path);


--
-- Name: scim_tokens uq_scim_tokens_token_hash; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scim_tokens
    ADD CONSTRAINT uq_scim_tokens_token_hash UNIQUE (token_hash);


--
-- Name: semgrep_rules uq_semgrep_rules_source_hash; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.semgrep_rules
    ADD CONSTRAINT uq_semgrep_rules_source_hash UNIQUE (source_id, content_hash);


--
-- Name: sso_providers uq_sso_providers_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_providers
    ADD CONSTRAINT uq_sso_providers_name UNIQUE (name);


--
-- Name: tenant_retention_policies uq_tenant_retention_policy_class; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_retention_policies
    ADD CONSTRAINT uq_tenant_retention_policy_class UNIQUE (tenant_id, data_class);


--
-- Name: tenant_verified_domains uq_tenant_verified_domains_domain; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_verified_domains
    ADD CONSTRAINT uq_tenant_verified_domains_domain UNIQUE (domain);


--
-- Name: tenants uq_tenants_slug; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT uq_tenants_slug UNIQUE (slug);


--
-- Name: usage_budget_allocations uq_usage_budget_allocation; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_allocations
    ADD CONSTRAINT uq_usage_budget_allocation UNIQUE (reservation_id, counter_id);


--
-- Name: usage_budget_counters uq_usage_budget_counter_window; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_counters
    ADD CONSTRAINT uq_usage_budget_counter_window UNIQUE (policy_id, window_key);


--
-- Name: usage_budget_notification_outbox uq_usage_budget_notification_recipient; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_notification_outbox
    ADD CONSTRAINT uq_usage_budget_notification_recipient UNIQUE (threshold_event_id, recipient_user_id);


--
-- Name: usage_budget_policies uq_usage_budget_policy_version; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_policies
    ADD CONSTRAINT uq_usage_budget_policy_version UNIQUE (logical_policy_id, version);


--
-- Name: usage_budget_threshold_events uq_usage_budget_threshold_event; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_threshold_events
    ADD CONSTRAINT uq_usage_budget_threshold_event UNIQUE (counter_id, dimension, threshold_percent);


--
-- Name: user_groups uq_user_groups_tenant_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT uq_user_groups_tenant_name UNIQUE (tenant_id, name);


--
-- Name: webauthn_credentials uq_webauthn_credentials_credential_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_credentials
    ADD CONSTRAINT uq_webauthn_credentials_credential_id UNIQUE (credential_id);


--
-- Name: usage_budget_allocations usage_budget_allocations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_allocations
    ADD CONSTRAINT usage_budget_allocations_pkey PRIMARY KEY (id);


--
-- Name: usage_budget_counters usage_budget_counters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_counters
    ADD CONSTRAINT usage_budget_counters_pkey PRIMARY KEY (id);


--
-- Name: usage_budget_notification_outbox usage_budget_notification_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_notification_outbox
    ADD CONSTRAINT usage_budget_notification_outbox_pkey PRIMARY KEY (id);


--
-- Name: usage_budget_overrides usage_budget_overrides_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_overrides
    ADD CONSTRAINT usage_budget_overrides_pkey PRIMARY KEY (id);


--
-- Name: usage_budget_policies usage_budget_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_policies
    ADD CONSTRAINT usage_budget_policies_pkey PRIMARY KEY (id);


--
-- Name: usage_budget_reservations usage_budget_reservations_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_reservations
    ADD CONSTRAINT usage_budget_reservations_idempotency_key_key UNIQUE (idempotency_key);


--
-- Name: usage_budget_reservations usage_budget_reservations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_reservations
    ADD CONSTRAINT usage_budget_reservations_pkey PRIMARY KEY (id);


--
-- Name: usage_budget_settlements usage_budget_settlements_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_settlements
    ADD CONSTRAINT usage_budget_settlements_pkey PRIMARY KEY (id);


--
-- Name: usage_budget_settlements usage_budget_settlements_reservation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_settlements
    ADD CONSTRAINT usage_budget_settlements_reservation_id_key UNIQUE (reservation_id);


--
-- Name: usage_budget_settlements usage_budget_settlements_usage_event_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_settlements
    ADD CONSTRAINT usage_budget_settlements_usage_event_id_key UNIQUE (usage_event_id);


--
-- Name: usage_budget_threshold_events usage_budget_threshold_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_threshold_events
    ADD CONSTRAINT usage_budget_threshold_events_pkey PRIMARY KEY (id);


--
-- Name: user_group_memberships user_group_memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_group_memberships
    ADD CONSTRAINT user_group_memberships_pkey PRIMARY KEY (group_id, user_id);


--
-- Name: user_groups user_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_pkey PRIMARY KEY (id);


--
-- Name: user user_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT user_pkey PRIMARY KEY (id);


--
-- Name: webauthn_credentials webauthn_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_pkey PRIMARY KEY (id);


--
-- Name: ix_agents_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_agents_name ON public.agents USING btree (name);


--
-- Name: ix_approval_gates_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_approval_gates_attempt_id ON public.approval_gates USING btree (attempt_id);


--
-- Name: ix_approval_gates_resume_lease_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_approval_gates_resume_lease_expires_at ON public.approval_gates USING btree (resume_lease_expires_at);


--
-- Name: ix_approval_gates_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_approval_gates_scan_id ON public.approval_gates USING btree (scan_id);


--
-- Name: ix_auth_audit_events_actor_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_auth_audit_events_actor_user_id ON public.auth_audit_events USING btree (actor_user_id);


--
-- Name: ix_auth_audit_events_event; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_auth_audit_events_event ON public.auth_audit_events USING btree (event);


--
-- Name: ix_auth_audit_events_provider_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_auth_audit_events_provider_id ON public.auth_audit_events USING btree (provider_id);


--
-- Name: ix_auth_audit_events_session_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_auth_audit_events_session_id ON public.auth_audit_events USING btree (session_id);


--
-- Name: ix_auth_audit_events_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_auth_audit_events_tenant_id ON public.auth_audit_events USING btree (tenant_id);


--
-- Name: ix_auth_audit_events_ts_desc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_auth_audit_events_ts_desc ON public.auth_audit_events USING btree (ts DESC);


--
-- Name: ix_auth_audit_events_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_auth_audit_events_user_id ON public.auth_audit_events USING btree (user_id);


--
-- Name: ix_auth_sessions_absolute_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_auth_sessions_absolute_expires_at ON public.auth_sessions USING btree (absolute_expires_at);


--
-- Name: ix_auth_sessions_active_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_auth_sessions_active_tenant_id ON public.auth_sessions USING btree (active_tenant_id);


--
-- Name: ix_auth_sessions_idle_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_auth_sessions_idle_expires_at ON public.auth_sessions USING btree (idle_expires_at);


--
-- Name: ix_auth_sessions_provider_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_auth_sessions_provider_id ON public.auth_sessions USING btree (provider_id);


--
-- Name: ix_auth_sessions_provider_session_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_auth_sessions_provider_session_hash ON public.auth_sessions USING btree (provider_session_hash);


--
-- Name: ix_auth_sessions_revoked_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_auth_sessions_revoked_at ON public.auth_sessions USING btree (revoked_at);


--
-- Name: ix_auth_sessions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_auth_sessions_tenant_id ON public.auth_sessions USING btree (tenant_id);


--
-- Name: ix_auth_sessions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_auth_sessions_user_id ON public.auth_sessions USING btree (user_id);


--
-- Name: ix_authorization_action_requests_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_authorization_action_requests_expires_at ON public.authorization_action_requests USING btree (expires_at);


--
-- Name: ix_authorization_action_requests_requester_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_authorization_action_requests_requester_user_id ON public.authorization_action_requests USING btree (requester_user_id);


--
-- Name: ix_authorization_action_requests_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_authorization_action_requests_status ON public.authorization_action_requests USING btree (status);


--
-- Name: ix_authorization_action_requests_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_authorization_action_requests_tenant_id ON public.authorization_action_requests USING btree (tenant_id);


--
-- Name: ix_authorization_audit_events_action_request_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_authorization_audit_events_action_request_id ON public.authorization_audit_events USING btree (action_request_id);


--
-- Name: ix_authorization_audit_events_occurred_at_desc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_authorization_audit_events_occurred_at_desc ON public.authorization_audit_events USING btree (occurred_at DESC);


--
-- Name: ix_authorization_audit_events_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_authorization_audit_events_tenant_id ON public.authorization_audit_events USING btree (tenant_id);


--
-- Name: ix_chat_messages_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_chat_messages_expires_at ON public.chat_messages USING btree (expires_at) WHERE (expires_at IS NOT NULL);


--
-- Name: ix_chat_sessions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_chat_sessions_tenant_id ON public.chat_sessions USING btree (tenant_id);


--
-- Name: ix_evidence_governance_events_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_evidence_governance_events_attempt_id ON public.evidence_governance_events USING btree (attempt_id);


--
-- Name: ix_evidence_governance_events_evidence_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_evidence_governance_events_evidence_id ON public.evidence_governance_events USING btree (evidence_id);


--
-- Name: ix_evidence_governance_events_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_evidence_governance_events_scan_id ON public.evidence_governance_events USING btree (scan_id);


--
-- Name: ix_evidence_governance_events_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_evidence_governance_events_tenant_id ON public.evidence_governance_events USING btree (tenant_id);


--
-- Name: ix_evidence_manifests_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_evidence_manifests_attempt_id ON public.evidence_manifests USING btree (attempt_id);


--
-- Name: ix_evidence_manifests_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_evidence_manifests_scan_id ON public.evidence_manifests USING btree (scan_id);


--
-- Name: ix_evidence_objects_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_evidence_objects_attempt_id ON public.evidence_objects USING btree (attempt_id);


--
-- Name: ix_evidence_objects_retention; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_evidence_objects_retention ON public.evidence_objects USING btree (state, legal_hold, retain_until);


--
-- Name: ix_evidence_objects_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_evidence_objects_scan_id ON public.evidence_objects USING btree (scan_id);


--
-- Name: ix_evidence_objects_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_evidence_objects_tenant_id ON public.evidence_objects USING btree (tenant_id);


--
-- Name: ix_federation_replay_markers_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_replay_markers_expires_at ON public.federation_replay_markers USING btree (expires_at);


--
-- Name: ix_federation_replay_markers_provider_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_federation_replay_markers_provider_id ON public.federation_replay_markers USING btree (provider_id);


--
-- Name: ix_finding_disposition_events_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_disposition_events_finding_id ON public.finding_disposition_events USING btree (finding_id);


--
-- Name: ix_finding_fix_candidates_canonical_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_fix_candidates_canonical_finding_id ON public.finding_fix_candidates USING btree (canonical_finding_id);


--
-- Name: ix_finding_fix_candidates_patch_hunk_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_fix_candidates_patch_hunk_id ON public.finding_fix_candidates USING btree (patch_hunk_id);


--
-- Name: ix_finding_fix_candidates_raw_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_fix_candidates_raw_finding_id ON public.finding_fix_candidates USING btree (raw_finding_id);


--
-- Name: ix_finding_fix_candidates_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_fix_candidates_scan_id ON public.finding_fix_candidates USING btree (scan_id);


--
-- Name: ix_finding_lineage_records_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_lineage_records_attempt_id ON public.finding_lineage_records USING btree (attempt_id);


--
-- Name: ix_finding_lineage_records_baseline_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_lineage_records_baseline_state ON public.finding_lineage_records USING btree (baseline_state);


--
-- Name: ix_finding_lineage_records_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_lineage_records_created_at ON public.finding_lineage_records USING btree (created_at);


--
-- Name: ix_finding_lineage_records_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_lineage_records_finding_id ON public.finding_lineage_records USING btree (finding_id);


--
-- Name: ix_finding_lineage_records_fingerprint; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_lineage_records_fingerprint ON public.finding_lineage_records USING btree (fingerprint);


--
-- Name: ix_finding_lineage_records_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_lineage_records_project_id ON public.finding_lineage_records USING btree (project_id);


--
-- Name: ix_finding_lineage_records_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_lineage_records_scan_id ON public.finding_lineage_records USING btree (scan_id);


--
-- Name: ix_finding_lineage_records_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_lineage_records_tenant_id ON public.finding_lineage_records USING btree (tenant_id);


--
-- Name: ix_finding_policy_evaluations_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_policy_evaluations_attempt_id ON public.finding_policy_evaluations USING btree (attempt_id);


--
-- Name: ix_finding_policy_evaluations_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_policy_evaluations_created_at ON public.finding_policy_evaluations USING btree (created_at);


--
-- Name: ix_finding_policy_evaluations_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_policy_evaluations_project_id ON public.finding_policy_evaluations USING btree (project_id);


--
-- Name: ix_finding_policy_evaluations_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_policy_evaluations_scan_id ON public.finding_policy_evaluations USING btree (scan_id);


--
-- Name: ix_finding_policy_evaluations_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_policy_evaluations_tenant_id ON public.finding_policy_evaluations USING btree (tenant_id);


--
-- Name: ix_finding_policy_versions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_policy_versions_tenant_id ON public.finding_policy_versions USING btree (tenant_id);


--
-- Name: ix_finding_waiver_events_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_waiver_events_tenant_id ON public.finding_waiver_events USING btree (tenant_id);


--
-- Name: ix_finding_waiver_events_waiver_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_waiver_events_waiver_id ON public.finding_waiver_events USING btree (waiver_id);


--
-- Name: ix_finding_waivers_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_waivers_expires_at ON public.finding_waivers USING btree (expires_at);


--
-- Name: ix_finding_waivers_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_waivers_finding_id ON public.finding_waivers USING btree (finding_id);


--
-- Name: ix_finding_waivers_fingerprint; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_waivers_fingerprint ON public.finding_waivers USING btree (fingerprint);


--
-- Name: ix_finding_waivers_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_waivers_project_id ON public.finding_waivers USING btree (project_id);


--
-- Name: ix_finding_waivers_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_waivers_scan_id ON public.finding_waivers USING btree (scan_id);


--
-- Name: ix_finding_waivers_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_finding_waivers_tenant_id ON public.finding_waivers USING btree (tenant_id);


--
-- Name: ix_findings_canonical_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_canonical_finding_id ON public.findings USING btree (canonical_finding_id);


--
-- Name: ix_findings_coverage_entry_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_coverage_entry_id ON public.findings USING btree (coverage_entry_id);


--
-- Name: ix_findings_cve_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_cve_id ON public.findings USING btree (cve_id);


--
-- Name: ix_findings_disposition; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_disposition ON public.findings USING btree (disposition);


--
-- Name: ix_findings_raw_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_raw_finding_id ON public.findings USING btree (raw_finding_id);


--
-- Name: ix_findings_scan_bucket; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_scan_bucket ON public.findings USING btree (scan_id, finding_bucket);


--
-- Name: ix_findings_scanner_rule_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_scanner_rule_id ON public.findings USING btree (scanner_rule_id);


--
-- Name: ix_findings_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_source ON public.findings USING btree (source) WHERE (source IS NOT NULL);


--
-- Name: ix_findings_source_snapshot_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_source_snapshot_hash ON public.findings USING btree (source_snapshot_hash);


--
-- Name: ix_findings_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_tenant_id ON public.findings USING btree (tenant_id);


--
-- Name: ix_frameworks_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_frameworks_name ON public.frameworks USING btree (name);


--
-- Name: ix_governance_legal_holds_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_governance_legal_holds_tenant_id ON public.governance_legal_holds USING btree (tenant_id);


--
-- Name: ix_governance_operations_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_governance_operations_due ON public.governance_operations USING btree (created_at) WHERE ((status)::text = ANY ((ARRAY['prepared'::character varying, 'executing'::character varying])::text[]));


--
-- Name: ix_governance_operations_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_governance_operations_tenant_id ON public.governance_operations USING btree (tenant_id);


--
-- Name: ix_governance_store_actions_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_governance_store_actions_due ON public.governance_store_actions USING btree (lease_expires_at, created_at) WHERE ((status)::text = ANY ((ARRAY['pending'::character varying, 'leased'::character varying, 'failed'::character varying])::text[]));


--
-- Name: ix_governance_store_actions_operation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_governance_store_actions_operation_id ON public.governance_store_actions USING btree (operation_id);


--
-- Name: ix_governance_store_actions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_governance_store_actions_tenant_id ON public.governance_store_actions USING btree (tenant_id);


--
-- Name: ix_integration_delivery_audit_outbox_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_integration_delivery_audit_outbox_id ON public.integration_delivery_audit USING btree (outbox_id);


--
-- Name: ix_integration_delivery_audit_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_integration_delivery_audit_tenant_id ON public.integration_delivery_audit USING btree (tenant_id);


--
-- Name: ix_integration_finding_tickets_principal_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_integration_finding_tickets_principal_id ON public.integration_finding_tickets USING btree (principal_id);


--
-- Name: ix_integration_finding_tickets_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_integration_finding_tickets_tenant_id ON public.integration_finding_tickets USING btree (tenant_id);


--
-- Name: ix_integration_grants_principal_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_integration_grants_principal_id ON public.integration_grants USING btree (principal_id);


--
-- Name: ix_integration_grants_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_integration_grants_tenant_id ON public.integration_grants USING btree (tenant_id);


--
-- Name: ix_integration_inbound_receipts_principal_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_integration_inbound_receipts_principal_id ON public.integration_inbound_receipts USING btree (principal_id);


--
-- Name: ix_integration_inbound_receipts_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_integration_inbound_receipts_tenant_id ON public.integration_inbound_receipts USING btree (tenant_id);


--
-- Name: ix_integration_outbox_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_integration_outbox_due ON public.integration_outbox USING btree (next_attempt_at) WHERE ((state)::text = ANY ((ARRAY['pending'::character varying, 'retry'::character varying])::text[]));


--
-- Name: ix_integration_outbox_principal_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_integration_outbox_principal_id ON public.integration_outbox USING btree (principal_id);


--
-- Name: ix_integration_outbox_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_integration_outbox_tenant_id ON public.integration_outbox USING btree (tenant_id);


--
-- Name: ix_integration_service_principals_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_integration_service_principals_tenant_id ON public.integration_service_principals USING btree (tenant_id);


--
-- Name: ix_integration_source_submissions_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_integration_source_submissions_scan_id ON public.integration_source_submissions USING btree (scan_id);


--
-- Name: ix_integration_source_submissions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_integration_source_submissions_tenant_id ON public.integration_source_submissions USING btree (tenant_id);


--
-- Name: ix_integration_ticket_history_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_integration_ticket_history_tenant_id ON public.integration_ticket_history USING btree (tenant_id);


--
-- Name: ix_integration_ticket_history_ticket_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_integration_ticket_history_ticket_id ON public.integration_ticket_history USING btree (ticket_id);


--
-- Name: ix_llm_call_reservations_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_call_reservations_attempt_id ON public.llm_call_reservations USING btree (attempt_id);


--
-- Name: ix_llm_call_reservations_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_call_reservations_scan_id ON public.llm_call_reservations USING btree (scan_id);


--
-- Name: ix_llm_configurations_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_llm_configurations_name ON public.llm_configurations USING btree (name);


--
-- Name: ix_llm_interactions_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_interactions_expires_at ON public.llm_interactions USING btree (expires_at) WHERE (expires_at IS NOT NULL);


--
-- Name: ix_llm_interactions_llm_config_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_interactions_llm_config_id ON public.llm_interactions USING btree (llm_config_id);


--
-- Name: ix_llm_price_overrides_llm_config_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_price_overrides_llm_config_id ON public.llm_price_overrides USING btree (llm_config_id);


--
-- Name: ix_llm_usage_events_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_usage_events_attempt_id ON public.llm_usage_events USING btree (attempt_id);


--
-- Name: ix_llm_usage_events_chat_session_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_usage_events_chat_session_id ON public.llm_usage_events USING btree (chat_session_id);


--
-- Name: ix_llm_usage_events_llm_config_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_usage_events_llm_config_id ON public.llm_usage_events USING btree (llm_config_id);


--
-- Name: ix_llm_usage_events_operation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_usage_events_operation_id ON public.llm_usage_events USING btree (operation_id);


--
-- Name: ix_llm_usage_events_operation_kind; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_usage_events_operation_kind ON public.llm_usage_events USING btree (operation_kind);


--
-- Name: ix_llm_usage_events_rag_job_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_usage_events_rag_job_id ON public.llm_usage_events USING btree (rag_job_id);


--
-- Name: ix_llm_usage_events_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_usage_events_scan_id ON public.llm_usage_events USING btree (scan_id);


--
-- Name: ix_llm_usage_events_scan_task_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_usage_events_scan_task_id ON public.llm_usage_events USING btree (scan_task_id);


--
-- Name: ix_llm_usage_events_stage; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_usage_events_stage ON public.llm_usage_events USING btree (stage);


--
-- Name: ix_llm_usage_events_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_usage_events_tenant_id ON public.llm_usage_events USING btree (tenant_id);


--
-- Name: ix_llm_usage_events_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_usage_events_user_id ON public.llm_usage_events USING btree (user_id);


--
-- Name: ix_llm_usage_line_items_usage_request_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_usage_line_items_usage_request_id ON public.llm_usage_line_items USING btree (usage_request_id);


--
-- Name: ix_llm_usage_requests_provider_response_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_usage_requests_provider_response_id ON public.llm_usage_requests USING btree (provider_response_id);


--
-- Name: ix_llm_usage_requests_usage_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_llm_usage_requests_usage_event_id ON public.llm_usage_requests USING btree (usage_event_id);


--
-- Name: ix_oauth_accounts_provider_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_oauth_accounts_provider_id ON public.oauth_accounts USING btree (provider_id);


--
-- Name: ix_oauth_accounts_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_oauth_accounts_user_id ON public.oauth_accounts USING btree (user_id);


--
-- Name: ix_offline_bundle_deployments_bundle_sha256; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_offline_bundle_deployments_bundle_sha256 ON public.offline_bundle_deployments USING btree (bundle_sha256);


--
-- Name: ix_projects_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_projects_tenant_id ON public.projects USING btree (tenant_id);


--
-- Name: ix_prompt_templates_template_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_prompt_templates_template_type ON public.prompt_templates USING btree (template_type);


--
-- Name: ix_provider_billing_connectors_next_run_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_provider_billing_connectors_next_run_at ON public.provider_billing_connectors USING btree (next_run_at);


--
-- Name: ix_provider_billing_connectors_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_provider_billing_connectors_tenant_id ON public.provider_billing_connectors USING btree (tenant_id);


--
-- Name: ix_provider_reconciliation_adjustments_run_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_provider_reconciliation_adjustments_run_id ON public.provider_reconciliation_adjustments USING btree (run_id);


--
-- Name: ix_provider_reconciliation_adjustments_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_provider_reconciliation_adjustments_tenant_id ON public.provider_reconciliation_adjustments USING btree (tenant_id);


--
-- Name: ix_provider_reconciliation_alert_outbox_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_provider_reconciliation_alert_outbox_tenant_id ON public.provider_reconciliation_alert_outbox USING btree (tenant_id);


--
-- Name: ix_provider_reconciliation_evidence_classification; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_provider_reconciliation_evidence_classification ON public.provider_reconciliation_evidence USING btree (classification);


--
-- Name: ix_provider_reconciliation_evidence_run_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_provider_reconciliation_evidence_run_id ON public.provider_reconciliation_evidence USING btree (run_id);


--
-- Name: ix_provider_reconciliation_evidence_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_provider_reconciliation_evidence_tenant_id ON public.provider_reconciliation_evidence USING btree (tenant_id);


--
-- Name: ix_provider_reconciliation_runs_completed_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_provider_reconciliation_runs_completed_at ON public.provider_reconciliation_runs USING btree (completed_at);


--
-- Name: ix_provider_reconciliation_runs_connector_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_provider_reconciliation_runs_connector_id ON public.provider_reconciliation_runs USING btree (connector_id);


--
-- Name: ix_provider_reconciliation_runs_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_provider_reconciliation_runs_tenant_id ON public.provider_reconciliation_runs USING btree (tenant_id);


--
-- Name: ix_push_subscriptions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_push_subscriptions_user_id ON public.push_subscriptions USING btree (user_id);


--
-- Name: ix_rag_preprocessing_jobs_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rag_preprocessing_jobs_expires_at ON public.rag_preprocessing_jobs USING btree (expires_at) WHERE (expires_at IS NOT NULL);


--
-- Name: ix_rag_preprocessing_jobs_original_file_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rag_preprocessing_jobs_original_file_hash ON public.rag_preprocessing_jobs USING btree (original_file_hash);


--
-- Name: ix_role_assignments_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_role_assignments_tenant_id ON public.role_assignments USING btree (tenant_id);


--
-- Name: ix_role_assignments_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_role_assignments_user_id ON public.role_assignments USING btree (user_id);


--
-- Name: ix_rule_foundry_candidates_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_candidates_expires_at ON public.rule_foundry_candidates USING btree (expires_at);


--
-- Name: ix_rule_foundry_candidates_registry_kind; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_candidates_registry_kind ON public.rule_foundry_candidates USING btree (registry_kind);


--
-- Name: ix_rule_foundry_candidates_source_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_candidates_source_attempt_id ON public.rule_foundry_candidates USING btree (source_attempt_id);


--
-- Name: ix_rule_foundry_candidates_source_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_candidates_source_finding_id ON public.rule_foundry_candidates USING btree (source_finding_id);


--
-- Name: ix_rule_foundry_candidates_source_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_candidates_source_scan_id ON public.rule_foundry_candidates USING btree (source_scan_id);


--
-- Name: ix_rule_foundry_candidates_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_candidates_status ON public.rule_foundry_candidates USING btree (status);


--
-- Name: ix_rule_foundry_candidates_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_candidates_tenant_id ON public.rule_foundry_candidates USING btree (tenant_id);


--
-- Name: ix_rule_foundry_deployments_candidate_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_deployments_candidate_id ON public.rule_foundry_deployments USING btree (candidate_id);


--
-- Name: ix_rule_foundry_deployments_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_deployments_state ON public.rule_foundry_deployments USING btree (state);


--
-- Name: ix_rule_foundry_deployments_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_deployments_tenant_id ON public.rule_foundry_deployments USING btree (tenant_id);


--
-- Name: ix_rule_foundry_deployments_version_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_deployments_version_id ON public.rule_foundry_deployments USING btree (version_id);


--
-- Name: ix_rule_foundry_events_candidate_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_events_candidate_id ON public.rule_foundry_events USING btree (candidate_id);


--
-- Name: ix_rule_foundry_events_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_events_created_at ON public.rule_foundry_events USING btree (created_at);


--
-- Name: ix_rule_foundry_events_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_events_tenant_id ON public.rule_foundry_events USING btree (tenant_id);


--
-- Name: ix_rule_foundry_gitleaks_candidates_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_gitleaks_candidates_tenant_id ON public.rule_foundry_gitleaks_candidates USING btree (tenant_id);


--
-- Name: ix_rule_foundry_osv_candidates_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_osv_candidates_tenant_id ON public.rule_foundry_osv_candidates USING btree (tenant_id);


--
-- Name: ix_rule_foundry_semgrep_candidates_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_semgrep_candidates_tenant_id ON public.rule_foundry_semgrep_candidates USING btree (tenant_id);


--
-- Name: ix_rule_foundry_shadow_observations_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_shadow_observations_attempt_id ON public.rule_foundry_shadow_observations USING btree (attempt_id);


--
-- Name: ix_rule_foundry_shadow_observations_deployment_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_shadow_observations_deployment_id ON public.rule_foundry_shadow_observations USING btree (deployment_id);


--
-- Name: ix_rule_foundry_shadow_observations_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_shadow_observations_scan_id ON public.rule_foundry_shadow_observations USING btree (scan_id);


--
-- Name: ix_rule_foundry_shadow_observations_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_shadow_observations_tenant_id ON public.rule_foundry_shadow_observations USING btree (tenant_id);


--
-- Name: ix_rule_foundry_versions_candidate_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_versions_candidate_id ON public.rule_foundry_versions USING btree (candidate_id);


--
-- Name: ix_rule_foundry_versions_payload_sha256; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_versions_payload_sha256 ON public.rule_foundry_versions USING btree (payload_sha256);


--
-- Name: ix_rule_foundry_versions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rule_foundry_versions_tenant_id ON public.rule_foundry_versions USING btree (tenant_id);


--
-- Name: ix_saml_subjects_provider_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_saml_subjects_provider_id ON public.saml_subjects USING btree (provider_id);


--
-- Name: ix_saml_subjects_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_saml_subjects_user_id ON public.saml_subjects USING btree (user_id);


--
-- Name: ix_scan_artifacts_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scan_artifacts_attempt_id ON public.scan_artifacts USING btree (attempt_id);


--
-- Name: ix_scan_artifacts_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scan_artifacts_scan_id ON public.scan_artifacts USING btree (scan_id);


--
-- Name: ix_scan_attempts_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scan_attempts_scan_id ON public.scan_attempts USING btree (scan_id);


--
-- Name: ix_scan_attempts_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scan_attempts_tenant_id ON public.scan_attempts USING btree (tenant_id);


--
-- Name: ix_scan_events_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scan_events_attempt_id ON public.scan_events USING btree (attempt_id);


--
-- Name: ix_scan_outbox_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scan_outbox_attempt_id ON public.scan_outbox USING btree (attempt_id);


--
-- Name: ix_scan_outbox_unpublished; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scan_outbox_unpublished ON public.scan_outbox USING btree (created_at) WHERE (published_at IS NULL);


--
-- Name: ix_scan_tasks_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scan_tasks_attempt_id ON public.scan_tasks USING btree (attempt_id);


--
-- Name: ix_scan_tasks_lease_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scan_tasks_lease_expires_at ON public.scan_tasks USING btree (lease_expires_at);


--
-- Name: ix_scan_tasks_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scan_tasks_scan_id ON public.scan_tasks USING btree (scan_id);


--
-- Name: ix_scan_tasks_scan_type_input_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scan_tasks_scan_type_input_hash ON public.scan_tasks USING btree (scan_id, task_type, input_hash);


--
-- Name: ix_scan_tasks_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scan_tasks_status ON public.scan_tasks USING btree (status);


--
-- Name: ix_scanner_coverage_entries_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scanner_coverage_entries_attempt_id ON public.scanner_coverage_entries USING btree (attempt_id);


--
-- Name: ix_scanner_coverage_entries_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scanner_coverage_entries_scan_id ON public.scanner_coverage_entries USING btree (scan_id);


--
-- Name: ix_scanner_coverage_entries_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scanner_coverage_entries_tenant_id ON public.scanner_coverage_entries USING btree (tenant_id);


--
-- Name: ix_scanner_coverage_policy_decisions_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scanner_coverage_policy_decisions_attempt_id ON public.scanner_coverage_policy_decisions USING btree (attempt_id);


--
-- Name: ix_scanner_coverage_policy_decisions_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scanner_coverage_policy_decisions_scan_id ON public.scanner_coverage_policy_decisions USING btree (scan_id);


--
-- Name: ix_scanner_coverage_policy_decisions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scanner_coverage_policy_decisions_tenant_id ON public.scanner_coverage_policy_decisions USING btree (tenant_id);


--
-- Name: ix_scans_current_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scans_current_attempt_id ON public.scans USING btree (current_attempt_id);


--
-- Name: ix_scans_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scans_tenant_id ON public.scans USING btree (tenant_id);


--
-- Name: ix_scim_tokens_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scim_tokens_tenant_id ON public.scim_tokens USING btree (tenant_id);


--
-- Name: ix_semgrep_rule_sources_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_semgrep_rule_sources_slug ON public.semgrep_rule_sources USING btree (slug);


--
-- Name: ix_semgrep_rules_content_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_semgrep_rules_content_hash ON public.semgrep_rules USING btree (content_hash);


--
-- Name: ix_semgrep_rules_languages_gin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_semgrep_rules_languages_gin ON public.semgrep_rules USING gin (languages);


--
-- Name: ix_semgrep_rules_license_spdx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_semgrep_rules_license_spdx ON public.semgrep_rules USING btree (license_spdx);


--
-- Name: ix_semgrep_rules_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_semgrep_rules_severity ON public.semgrep_rules USING btree (severity);


--
-- Name: ix_semgrep_rules_source_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_semgrep_rules_source_id ON public.semgrep_rules USING btree (source_id);


--
-- Name: ix_semgrep_rules_technology_gin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_semgrep_rules_technology_gin ON public.semgrep_rules USING gin (technology);


--
-- Name: ix_semgrep_sync_runs_source_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_semgrep_sync_runs_source_id ON public.semgrep_sync_runs USING btree (source_id);


--
-- Name: ix_tenant_retention_policies_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_tenant_retention_policies_tenant_id ON public.tenant_retention_policies USING btree (tenant_id);


--
-- Name: ix_tenant_verified_domains_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_tenant_verified_domains_tenant_id ON public.tenant_verified_domains USING btree (tenant_id);


--
-- Name: ix_usage_budget_allocations_counter_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_allocations_counter_id ON public.usage_budget_allocations USING btree (counter_id);


--
-- Name: ix_usage_budget_allocations_reservation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_allocations_reservation_id ON public.usage_budget_allocations USING btree (reservation_id);


--
-- Name: ix_usage_budget_allocations_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_allocations_tenant_id ON public.usage_budget_allocations USING btree (tenant_id);


--
-- Name: ix_usage_budget_counters_policy_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_counters_policy_id ON public.usage_budget_counters USING btree (policy_id);


--
-- Name: ix_usage_budget_counters_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_counters_tenant_id ON public.usage_budget_counters USING btree (tenant_id);


--
-- Name: ix_usage_budget_notification_outbox_recipient_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_notification_outbox_recipient_user_id ON public.usage_budget_notification_outbox USING btree (recipient_user_id);


--
-- Name: ix_usage_budget_notification_outbox_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_notification_outbox_tenant_id ON public.usage_budget_notification_outbox USING btree (tenant_id);


--
-- Name: ix_usage_budget_notification_outbox_threshold_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_notification_outbox_threshold_event_id ON public.usage_budget_notification_outbox USING btree (threshold_event_id);


--
-- Name: ix_usage_budget_overrides_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_overrides_expires_at ON public.usage_budget_overrides USING btree (expires_at);


--
-- Name: ix_usage_budget_overrides_policy_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_overrides_policy_id ON public.usage_budget_overrides USING btree (policy_id);


--
-- Name: ix_usage_budget_overrides_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_overrides_tenant_id ON public.usage_budget_overrides USING btree (tenant_id);


--
-- Name: ix_usage_budget_policies_logical_policy_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_policies_logical_policy_id ON public.usage_budget_policies USING btree (logical_policy_id);


--
-- Name: ix_usage_budget_policies_target_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_policies_target_group_id ON public.usage_budget_policies USING btree (target_group_id);


--
-- Name: ix_usage_budget_policies_target_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_policies_target_user_id ON public.usage_budget_policies USING btree (target_user_id);


--
-- Name: ix_usage_budget_policies_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_policies_tenant_id ON public.usage_budget_policies USING btree (tenant_id);


--
-- Name: ix_usage_budget_reservations_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_reservations_expires_at ON public.usage_budget_reservations USING btree (expires_at);


--
-- Name: ix_usage_budget_reservations_parent_reservation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_reservations_parent_reservation_id ON public.usage_budget_reservations USING btree (parent_reservation_id);


--
-- Name: ix_usage_budget_reservations_scan_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_reservations_scan_attempt_id ON public.usage_budget_reservations USING btree (scan_attempt_id);


--
-- Name: ix_usage_budget_reservations_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_reservations_tenant_id ON public.usage_budget_reservations USING btree (tenant_id);


--
-- Name: ix_usage_budget_settlements_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_settlements_tenant_id ON public.usage_budget_settlements USING btree (tenant_id);


--
-- Name: ix_usage_budget_threshold_events_counter_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_threshold_events_counter_id ON public.usage_budget_threshold_events USING btree (counter_id);


--
-- Name: ix_usage_budget_threshold_events_policy_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_threshold_events_policy_id ON public.usage_budget_threshold_events USING btree (policy_id);


--
-- Name: ix_usage_budget_threshold_events_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_budget_threshold_events_tenant_id ON public.usage_budget_threshold_events USING btree (tenant_id);


--
-- Name: ix_user_email; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_user_email ON public."user" USING btree (email);


--
-- Name: ix_user_group_memberships_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_user_group_memberships_user_id ON public.user_group_memberships USING btree (user_id);


--
-- Name: ix_user_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_user_tenant_id ON public."user" USING btree (tenant_id);


--
-- Name: ix_webauthn_credentials_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_webauthn_credentials_user_id ON public.webauthn_credentials USING btree (user_id);


--
-- Name: uq_approval_gates_one_active_per_scan; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_approval_gates_one_active_per_scan ON public.approval_gates USING btree (scan_id) WHERE ((state)::text = ANY ((ARRAY['pending'::character varying, 'decided'::character varying, 'resume_claimed'::character varying])::text[]));


--
-- Name: uq_governance_legal_hold_active_scope; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_governance_legal_hold_active_scope ON public.governance_legal_holds USING btree (tenant_id, scope_type, scope_id) WHERE (released_at IS NULL);


--
-- Name: uq_integration_grant_active_scope; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_integration_grant_active_scope ON public.integration_grants USING btree (principal_id, feature, scope_digest) WHERE (revoked_at IS NULL);


--
-- Name: uq_offline_bundle_one_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_offline_bundle_one_active ON public.offline_bundle_deployments USING btree (status) WHERE ((status)::text = 'active'::text);


--
-- Name: uq_role_assignments_global_user_role; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_role_assignments_global_user_role ON public.role_assignments USING btree (user_id, role_key) WHERE (tenant_id IS NULL);


--
-- Name: uq_role_assignments_tenant_user_role; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_role_assignments_tenant_user_role ON public.role_assignments USING btree (tenant_id, user_id, role_key) WHERE (tenant_id IS NOT NULL);


--
-- Name: uq_rule_foundry_active_deployment; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_rule_foundry_active_deployment ON public.rule_foundry_deployments USING btree (tenant_id, candidate_id) WHERE (ended_at IS NULL);


--
-- Name: uq_scan_attempts_one_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_scan_attempts_one_active ON public.scan_attempts USING btree (scan_id) WHERE ((status)::text = 'active'::text);


--
-- Name: uq_scan_events_cancellation_phase; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_scan_events_cancellation_phase ON public.scan_events USING btree (scan_id, attempt_id, status) WHERE ((stage_name)::text = 'CANCELLATION'::text);


--
-- Name: auth_audit_events auth_audit_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER auth_audit_immutable BEFORE DELETE OR UPDATE ON public.auth_audit_events FOR EACH ROW EXECUTE FUNCTION public.auth_audit_events_block_modify();


--
-- Name: authorization_audit_events authorization_audit_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER authorization_audit_immutable BEFORE DELETE OR UPDATE ON public.authorization_audit_events FOR EACH ROW EXECUTE FUNCTION public.authorization_audit_events_block_modify();


--
-- Name: findings sccap_finding_coverage_tenant; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_finding_coverage_tenant BEFORE INSERT OR UPDATE OF tenant_id, coverage_entry_id, coverage_entry_ids ON public.findings FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_finding_coverage_tenant();


--
-- Name: finding_lineage_records sccap_finding_governance_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_finding_governance_immutable BEFORE DELETE OR UPDATE ON public.finding_lineage_records FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_finding_governance_mutation();


--
-- Name: finding_policy_evaluations sccap_finding_governance_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_finding_governance_immutable BEFORE DELETE OR UPDATE ON public.finding_policy_evaluations FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_finding_governance_mutation();


--
-- Name: finding_policy_versions sccap_finding_governance_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_finding_governance_immutable BEFORE DELETE OR UPDATE ON public.finding_policy_versions FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_finding_governance_mutation();


--
-- Name: finding_waiver_events sccap_finding_governance_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_finding_governance_immutable BEFORE DELETE OR UPDATE ON public.finding_waiver_events FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_finding_governance_mutation();


--
-- Name: finding_waivers sccap_finding_governance_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_finding_governance_immutable BEFORE DELETE OR UPDATE ON public.finding_waivers FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_finding_governance_mutation();


--
-- Name: user_group_memberships sccap_group_membership_tenant; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_group_membership_tenant BEFORE INSERT OR UPDATE OF group_id, user_id ON public.user_group_memberships FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_group_membership_tenant();


--
-- Name: integration_delivery_audit sccap_integration_evidence_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_integration_evidence_immutable BEFORE DELETE OR UPDATE ON public.integration_delivery_audit FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_integration_evidence_mutation();


--
-- Name: integration_inbound_receipts sccap_integration_evidence_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_integration_evidence_immutable BEFORE DELETE OR UPDATE ON public.integration_inbound_receipts FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_integration_evidence_mutation();


--
-- Name: integration_source_submissions sccap_integration_evidence_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_integration_evidence_immutable BEFORE DELETE OR UPDATE ON public.integration_source_submissions FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_integration_evidence_mutation();


--
-- Name: integration_ticket_history sccap_integration_evidence_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_integration_evidence_immutable BEFORE DELETE OR UPDATE ON public.integration_ticket_history FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_integration_evidence_mutation();


--
-- Name: provider_reconciliation_adjustments sccap_provider_reconciliation_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_provider_reconciliation_immutable BEFORE DELETE OR UPDATE ON public.provider_reconciliation_adjustments FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_provider_reconciliation_mutation();


--
-- Name: provider_reconciliation_evidence sccap_provider_reconciliation_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_provider_reconciliation_immutable BEFORE DELETE OR UPDATE ON public.provider_reconciliation_evidence FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_provider_reconciliation_mutation();


--
-- Name: provider_reconciliation_runs sccap_provider_reconciliation_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_provider_reconciliation_immutable BEFORE DELETE OR UPDATE ON public.provider_reconciliation_runs FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_provider_reconciliation_mutation();


--
-- Name: rule_foundry_events sccap_rule_foundry_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_immutable BEFORE DELETE OR UPDATE ON public.rule_foundry_events FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_rule_foundry_evidence_mutation();


--
-- Name: rule_foundry_gitleaks_candidates sccap_rule_foundry_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_immutable BEFORE DELETE OR UPDATE ON public.rule_foundry_gitleaks_candidates FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_rule_foundry_evidence_mutation();


--
-- Name: rule_foundry_osv_candidates sccap_rule_foundry_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_immutable BEFORE DELETE OR UPDATE ON public.rule_foundry_osv_candidates FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_rule_foundry_evidence_mutation();


--
-- Name: rule_foundry_semgrep_candidates sccap_rule_foundry_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_immutable BEFORE DELETE OR UPDATE ON public.rule_foundry_semgrep_candidates FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_rule_foundry_evidence_mutation();


--
-- Name: rule_foundry_shadow_observations sccap_rule_foundry_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_immutable BEFORE DELETE OR UPDATE ON public.rule_foundry_shadow_observations FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_rule_foundry_evidence_mutation();


--
-- Name: rule_foundry_versions sccap_rule_foundry_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_immutable BEFORE DELETE OR UPDATE ON public.rule_foundry_versions FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_rule_foundry_evidence_mutation();


--
-- Name: rule_foundry_candidates sccap_rule_foundry_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, source_finding_id ON public.rule_foundry_candidates FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('findings', 'id', 'source_finding_id');


--
-- Name: rule_foundry_deployments sccap_rule_foundry_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, candidate_id ON public.rule_foundry_deployments FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('rule_foundry_candidates', 'id', 'candidate_id');


--
-- Name: rule_foundry_events sccap_rule_foundry_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, candidate_id ON public.rule_foundry_events FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('rule_foundry_candidates', 'id', 'candidate_id');


--
-- Name: rule_foundry_gitleaks_candidates sccap_rule_foundry_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, candidate_id ON public.rule_foundry_gitleaks_candidates FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('rule_foundry_candidates', 'id', 'candidate_id');


--
-- Name: rule_foundry_osv_candidates sccap_rule_foundry_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, candidate_id ON public.rule_foundry_osv_candidates FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('rule_foundry_candidates', 'id', 'candidate_id');


--
-- Name: rule_foundry_semgrep_candidates sccap_rule_foundry_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, candidate_id ON public.rule_foundry_semgrep_candidates FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('rule_foundry_candidates', 'id', 'candidate_id');


--
-- Name: rule_foundry_shadow_observations sccap_rule_foundry_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, deployment_id ON public.rule_foundry_shadow_observations FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('rule_foundry_deployments', 'id', 'deployment_id');


--
-- Name: rule_foundry_versions sccap_rule_foundry_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, candidate_id ON public.rule_foundry_versions FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('rule_foundry_candidates', 'id', 'candidate_id');


--
-- Name: rule_foundry_candidates sccap_rule_foundry_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, source_scan_id ON public.rule_foundry_candidates FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scans', 'id', 'source_scan_id');


--
-- Name: rule_foundry_deployments sccap_rule_foundry_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, version_id ON public.rule_foundry_deployments FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('rule_foundry_versions', 'id', 'version_id');


--
-- Name: rule_foundry_events sccap_rule_foundry_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, actor_user_id ON public.rule_foundry_events FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'actor_user_id');


--
-- Name: rule_foundry_shadow_observations sccap_rule_foundry_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, scan_id ON public.rule_foundry_shadow_observations FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scans', 'id', 'scan_id');


--
-- Name: rule_foundry_versions sccap_rule_foundry_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, reviewer_user_id ON public.rule_foundry_versions FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'reviewer_user_id');


--
-- Name: rule_foundry_candidates sccap_rule_foundry_tenant_reference_2; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_2 BEFORE INSERT OR UPDATE OF tenant_id, source_attempt_id ON public.rule_foundry_candidates FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scan_attempts', 'id', 'source_attempt_id');


--
-- Name: rule_foundry_deployments sccap_rule_foundry_tenant_reference_2; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_2 BEFORE INSERT OR UPDATE OF tenant_id, prior_version_id ON public.rule_foundry_deployments FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('rule_foundry_versions', 'id', 'prior_version_id');


--
-- Name: rule_foundry_shadow_observations sccap_rule_foundry_tenant_reference_2; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_2 BEFORE INSERT OR UPDATE OF tenant_id, attempt_id ON public.rule_foundry_shadow_observations FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scan_attempts', 'id', 'attempt_id');


--
-- Name: rule_foundry_candidates sccap_rule_foundry_tenant_reference_3; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_3 BEFORE INSERT OR UPDATE OF tenant_id, creator_user_id ON public.rule_foundry_candidates FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'creator_user_id');


--
-- Name: rule_foundry_deployments sccap_rule_foundry_tenant_reference_3; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_3 BEFORE INSERT OR UPDATE OF tenant_id, actor_user_id ON public.rule_foundry_deployments FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'actor_user_id');


--
-- Name: rule_foundry_candidates sccap_rule_foundry_tenant_reference_4; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_4 BEFORE INSERT OR UPDATE OF tenant_id, reviewer_user_id ON public.rule_foundry_candidates FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'reviewer_user_id');


--
-- Name: rule_foundry_candidates sccap_rule_foundry_tenant_reference_5; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_rule_foundry_tenant_reference_5 BEFORE INSERT OR UPDATE OF tenant_id, promoter_user_id ON public.rule_foundry_candidates FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'promoter_user_id');


--
-- Name: authorization_action_requests sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, requester_user_id ON public.authorization_action_requests FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'requester_user_id');


--
-- Name: chat_sessions sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.chat_sessions FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'user_id');


--
-- Name: evidence_governance_events sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, scan_id ON public.evidence_governance_events FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scans', 'id', 'scan_id');


--
-- Name: evidence_objects sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, scan_id ON public.evidence_objects FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scans', 'id', 'scan_id');


--
-- Name: finding_lineage_records sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, project_id ON public.finding_lineage_records FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('projects', 'id', 'project_id');


--
-- Name: finding_policy_evaluations sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, project_id ON public.finding_policy_evaluations FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('projects', 'id', 'project_id');


--
-- Name: finding_policy_versions sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, actor_user_id ON public.finding_policy_versions FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'actor_user_id');


--
-- Name: finding_waiver_events sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, waiver_id ON public.finding_waiver_events FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('finding_waivers', 'id', 'waiver_id');


--
-- Name: finding_waivers sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, project_id ON public.finding_waivers FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('projects', 'id', 'project_id');


--
-- Name: findings sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, scan_id ON public.findings FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scans', 'id', 'scan_id');


--
-- Name: governance_store_actions sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, operation_id ON public.governance_store_actions FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('governance_operations', 'id', 'operation_id');


--
-- Name: integration_delivery_audit sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, outbox_id ON public.integration_delivery_audit FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('integration_outbox', 'id', 'outbox_id');


--
-- Name: integration_finding_tickets sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, principal_id ON public.integration_finding_tickets FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('integration_service_principals', 'id', 'principal_id');


--
-- Name: integration_grants sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, principal_id ON public.integration_grants FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('integration_service_principals', 'id', 'principal_id');


--
-- Name: integration_inbound_receipts sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, principal_id ON public.integration_inbound_receipts FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('integration_service_principals', 'id', 'principal_id');


--
-- Name: integration_outbox sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, principal_id ON public.integration_outbox FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('integration_service_principals', 'id', 'principal_id');


--
-- Name: integration_service_principals sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, created_by_user_id ON public.integration_service_principals FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'created_by_user_id');


--
-- Name: integration_source_submissions sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, scan_id ON public.integration_source_submissions FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scans', 'id', 'scan_id');


--
-- Name: integration_ticket_history sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, ticket_id ON public.integration_ticket_history FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('integration_finding_tickets', 'id', 'ticket_id');


--
-- Name: llm_usage_events sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, scan_id ON public.llm_usage_events FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scans', 'id', 'scan_id');


--
-- Name: projects sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.projects FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'user_id');


--
-- Name: provider_billing_connectors sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, created_by_user_id ON public.provider_billing_connectors FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'created_by_user_id');


--
-- Name: provider_reconciliation_adjustments sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, run_id ON public.provider_reconciliation_adjustments FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('provider_reconciliation_runs', 'id', 'run_id');


--
-- Name: provider_reconciliation_alert_outbox sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, run_id ON public.provider_reconciliation_alert_outbox FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('provider_reconciliation_runs', 'id', 'run_id');


--
-- Name: provider_reconciliation_evidence sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, run_id ON public.provider_reconciliation_evidence FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('provider_reconciliation_runs', 'id', 'run_id');


--
-- Name: provider_reconciliation_runs sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, connector_id ON public.provider_reconciliation_runs FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('provider_billing_connectors', 'id', 'connector_id');


--
-- Name: scan_attempts sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, scan_id ON public.scan_attempts FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scans', 'id', 'scan_id');


--
-- Name: scanner_coverage_entries sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, scan_id ON public.scanner_coverage_entries FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scans', 'id', 'scan_id');


--
-- Name: scanner_coverage_policy_decisions sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, scan_id ON public.scanner_coverage_policy_decisions FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scans', 'id', 'scan_id');


--
-- Name: scans sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, project_id ON public.scans FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('projects', 'id', 'project_id');


--
-- Name: scim_tokens sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, created_by_user_id ON public.scim_tokens FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'created_by_user_id');


--
-- Name: usage_budget_allocations sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, reservation_id ON public.usage_budget_allocations FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('usage_budget_reservations', 'id', 'reservation_id');


--
-- Name: usage_budget_counters sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, policy_id ON public.usage_budget_counters FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('usage_budget_policies', 'id', 'policy_id');


--
-- Name: usage_budget_notification_outbox sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, threshold_event_id ON public.usage_budget_notification_outbox FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('usage_budget_threshold_events', 'id', 'threshold_event_id');


--
-- Name: usage_budget_overrides sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, policy_id ON public.usage_budget_overrides FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('usage_budget_policies', 'id', 'policy_id');


--
-- Name: usage_budget_policies sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, target_group_id ON public.usage_budget_policies FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user_groups', 'id', 'target_group_id');


--
-- Name: usage_budget_reservations sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, actor_user_id ON public.usage_budget_reservations FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'actor_user_id');


--
-- Name: usage_budget_settlements sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, reservation_id ON public.usage_budget_settlements FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('usage_budget_reservations', 'id', 'reservation_id');


--
-- Name: usage_budget_threshold_events sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, policy_id ON public.usage_budget_threshold_events FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('usage_budget_policies', 'id', 'policy_id');


--
-- Name: user_groups sccap_tenant_reference_0; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_0 BEFORE INSERT OR UPDATE OF tenant_id, created_by ON public.user_groups FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'created_by');


--
-- Name: chat_sessions sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, project_id ON public.chat_sessions FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('projects', 'id', 'project_id');


--
-- Name: evidence_governance_events sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, attempt_id ON public.evidence_governance_events FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scan_attempts', 'id', 'attempt_id');


--
-- Name: evidence_objects sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, attempt_id ON public.evidence_objects FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scan_attempts', 'id', 'attempt_id');


--
-- Name: finding_lineage_records sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, scan_id ON public.finding_lineage_records FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scans', 'id', 'scan_id');


--
-- Name: finding_policy_evaluations sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, scan_id ON public.finding_policy_evaluations FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scans', 'id', 'scan_id');


--
-- Name: finding_waiver_events sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, actor_user_id ON public.finding_waiver_events FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'actor_user_id');


--
-- Name: finding_waivers sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, scan_id ON public.finding_waivers FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scans', 'id', 'scan_id');


--
-- Name: integration_delivery_audit sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, principal_id ON public.integration_delivery_audit FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('integration_service_principals', 'id', 'principal_id');


--
-- Name: integration_grants sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, created_by_user_id ON public.integration_grants FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'created_by_user_id');


--
-- Name: integration_service_principals sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, revoked_by_user_id ON public.integration_service_principals FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'revoked_by_user_id');


--
-- Name: integration_source_submissions sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, created_by_user_id ON public.integration_source_submissions FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'created_by_user_id');


--
-- Name: llm_usage_events sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, chat_session_id ON public.llm_usage_events FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('chat_sessions', 'id', 'chat_session_id');


--
-- Name: provider_reconciliation_adjustments sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, evidence_id ON public.provider_reconciliation_adjustments FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('provider_reconciliation_evidence', 'id', 'evidence_id');


--
-- Name: scanner_coverage_entries sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, attempt_id ON public.scanner_coverage_entries FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scan_attempts', 'id', 'attempt_id');


--
-- Name: scanner_coverage_policy_decisions sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, attempt_id ON public.scanner_coverage_policy_decisions FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scan_attempts', 'id', 'attempt_id');


--
-- Name: scans sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.scans FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'user_id');


--
-- Name: usage_budget_allocations sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, counter_id ON public.usage_budget_allocations FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('usage_budget_counters', 'id', 'counter_id');


--
-- Name: usage_budget_notification_outbox sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, recipient_user_id ON public.usage_budget_notification_outbox FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'recipient_user_id');


--
-- Name: usage_budget_overrides sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, created_by_user_id ON public.usage_budget_overrides FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'created_by_user_id');


--
-- Name: usage_budget_policies sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, target_user_id ON public.usage_budget_policies FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'target_user_id');


--
-- Name: usage_budget_reservations sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, scan_attempt_id ON public.usage_budget_reservations FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scan_attempts', 'id', 'scan_attempt_id');


--
-- Name: usage_budget_settlements sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, usage_event_id ON public.usage_budget_settlements FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('llm_usage_events', 'id', 'usage_event_id');


--
-- Name: usage_budget_threshold_events sccap_tenant_reference_1; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_1 BEFORE INSERT OR UPDATE OF tenant_id, counter_id ON public.usage_budget_threshold_events FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('usage_budget_counters', 'id', 'counter_id');


--
-- Name: evidence_governance_events sccap_tenant_reference_2; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_2 BEFORE INSERT OR UPDATE OF tenant_id, evidence_id ON public.evidence_governance_events FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('evidence_objects', 'id', 'evidence_id');


--
-- Name: finding_lineage_records sccap_tenant_reference_2; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_2 BEFORE INSERT OR UPDATE OF tenant_id, attempt_id ON public.finding_lineage_records FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scan_attempts', 'id', 'attempt_id');


--
-- Name: finding_policy_evaluations sccap_tenant_reference_2; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_2 BEFORE INSERT OR UPDATE OF tenant_id, attempt_id ON public.finding_policy_evaluations FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('scan_attempts', 'id', 'attempt_id');


--
-- Name: finding_waivers sccap_tenant_reference_2; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_2 BEFORE INSERT OR UPDATE OF tenant_id, finding_id ON public.finding_waivers FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('findings', 'id', 'finding_id');


--
-- Name: integration_grants sccap_tenant_reference_2; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_2 BEFORE INSERT OR UPDATE OF tenant_id, revoked_by_user_id ON public.integration_grants FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'revoked_by_user_id');


--
-- Name: llm_usage_events sccap_tenant_reference_2; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_2 BEFORE INSERT OR UPDATE OF tenant_id, user_id ON public.llm_usage_events FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'user_id');


--
-- Name: scanner_coverage_policy_decisions sccap_tenant_reference_2; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_2 BEFORE INSERT OR UPDATE OF tenant_id, actor_user_id ON public.scanner_coverage_policy_decisions FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'actor_user_id');


--
-- Name: usage_budget_policies sccap_tenant_reference_2; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_2 BEFORE INSERT OR UPDATE OF tenant_id, created_by_user_id ON public.usage_budget_policies FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'created_by_user_id');


--
-- Name: finding_lineage_records sccap_tenant_reference_3; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_3 BEFORE INSERT OR UPDATE OF tenant_id, finding_id ON public.finding_lineage_records FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('findings', 'id', 'finding_id');


--
-- Name: finding_policy_evaluations sccap_tenant_reference_3; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_3 BEFORE INSERT OR UPDATE OF tenant_id, policy_version_id ON public.finding_policy_evaluations FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('finding_policy_versions', 'id', 'policy_version_id');


--
-- Name: finding_waivers sccap_tenant_reference_3; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_3 BEFORE INSERT OR UPDATE OF tenant_id, actor_user_id ON public.finding_waivers FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('user', 'id', 'actor_user_id');


--
-- Name: finding_lineage_records sccap_tenant_reference_4; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_tenant_reference_4 BEFORE INSERT OR UPDATE OF tenant_id, predecessor_finding_id ON public.finding_lineage_records FOR EACH ROW EXECUTE FUNCTION public.sccap_enforce_tenant_reference('findings', 'id', 'predecessor_finding_id');


--
-- Name: usage_budget_overrides sccap_usage_budget_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_usage_budget_immutable BEFORE DELETE OR UPDATE ON public.usage_budget_overrides FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_usage_budget_mutation();


--
-- Name: usage_budget_policies sccap_usage_budget_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_usage_budget_immutable BEFORE DELETE OR UPDATE ON public.usage_budget_policies FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_usage_budget_mutation();


--
-- Name: usage_budget_settlements sccap_usage_budget_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_usage_budget_immutable BEFORE DELETE OR UPDATE ON public.usage_budget_settlements FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_usage_budget_mutation();


--
-- Name: usage_budget_threshold_events sccap_usage_budget_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER sccap_usage_budget_immutable BEFORE DELETE OR UPDATE ON public.usage_budget_threshold_events FOR EACH ROW EXECUTE FUNCTION public.sccap_reject_usage_budget_mutation();


--
-- Name: authorization_action_requests authorization_action_requests_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_action_requests
    ADD CONSTRAINT authorization_action_requests_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: chat_messages chat_messages_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_messages
    ADD CONSTRAINT chat_messages_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.chat_sessions(id);


--
-- Name: chat_sessions chat_sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sessions
    ADD CONSTRAINT chat_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: code_snapshots code_snapshots_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.code_snapshots
    ADD CONSTRAINT code_snapshots_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id);


--
-- Name: cwe_owasp_mappings cwe_owasp_mappings_cwe_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cwe_owasp_mappings
    ADD CONSTRAINT cwe_owasp_mappings_cwe_id_fkey FOREIGN KEY (cwe_id) REFERENCES public.cwe_details(id);


--
-- Name: evidence_deletion_outbox evidence_deletion_outbox_evidence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_deletion_outbox
    ADD CONSTRAINT evidence_deletion_outbox_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES public.evidence_objects(id) ON DELETE CASCADE;


--
-- Name: evidence_governance_events evidence_governance_events_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_governance_events
    ADD CONSTRAINT evidence_governance_events_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: evidence_governance_events evidence_governance_events_attempt_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_governance_events
    ADD CONSTRAINT evidence_governance_events_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES public.scan_attempts(id) ON DELETE SET NULL;


--
-- Name: evidence_governance_events evidence_governance_events_evidence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_governance_events
    ADD CONSTRAINT evidence_governance_events_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES public.evidence_objects(id) ON DELETE SET NULL;


--
-- Name: evidence_governance_events evidence_governance_events_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_governance_events
    ADD CONSTRAINT evidence_governance_events_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE SET NULL;


--
-- Name: evidence_governance_events evidence_governance_events_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_governance_events
    ADD CONSTRAINT evidence_governance_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: evidence_manifests evidence_manifests_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_manifests
    ADD CONSTRAINT evidence_manifests_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: evidence_manifests evidence_manifests_attempt_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_manifests
    ADD CONSTRAINT evidence_manifests_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES public.scan_attempts(id) ON DELETE SET NULL;


--
-- Name: evidence_manifests evidence_manifests_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_manifests
    ADD CONSTRAINT evidence_manifests_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE SET NULL;


--
-- Name: evidence_objects evidence_objects_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_objects
    ADD CONSTRAINT evidence_objects_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: evidence_objects evidence_objects_attempt_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_objects
    ADD CONSTRAINT evidence_objects_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES public.scan_attempts(id) ON DELETE SET NULL;


--
-- Name: evidence_objects evidence_objects_legacy_artifact_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_objects
    ADD CONSTRAINT evidence_objects_legacy_artifact_id_fkey FOREIGN KEY (legacy_artifact_id) REFERENCES public.scan_artifacts(id) ON DELETE SET NULL;


--
-- Name: evidence_objects evidence_objects_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_objects
    ADD CONSTRAINT evidence_objects_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE SET NULL;


--
-- Name: evidence_objects evidence_objects_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_objects
    ADD CONSTRAINT evidence_objects_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: federation_replay_markers federation_replay_markers_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_replay_markers
    ADD CONSTRAINT federation_replay_markers_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.sso_providers(id) ON DELETE CASCADE;


--
-- Name: finding_disposition_events finding_disposition_events_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_disposition_events
    ADD CONSTRAINT finding_disposition_events_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: finding_disposition_events finding_disposition_events_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_disposition_events
    ADD CONSTRAINT finding_disposition_events_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: finding_fix_candidates finding_fix_candidates_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_fix_candidates
    ADD CONSTRAINT finding_fix_candidates_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: finding_lineage_records finding_lineage_records_attempt_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_lineage_records
    ADD CONSTRAINT finding_lineage_records_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES public.scan_attempts(id) ON DELETE SET NULL;


--
-- Name: finding_lineage_records finding_lineage_records_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_lineage_records
    ADD CONSTRAINT finding_lineage_records_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE SET NULL;


--
-- Name: finding_lineage_records finding_lineage_records_predecessor_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_lineage_records
    ADD CONSTRAINT finding_lineage_records_predecessor_finding_id_fkey FOREIGN KEY (predecessor_finding_id) REFERENCES public.findings(id) ON DELETE SET NULL;


--
-- Name: finding_lineage_records finding_lineage_records_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_lineage_records
    ADD CONSTRAINT finding_lineage_records_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE SET NULL;


--
-- Name: finding_lineage_records finding_lineage_records_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_lineage_records
    ADD CONSTRAINT finding_lineage_records_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE SET NULL;


--
-- Name: finding_lineage_records finding_lineage_records_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_lineage_records
    ADD CONSTRAINT finding_lineage_records_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: finding_policy_evaluations finding_policy_evaluations_attempt_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_policy_evaluations
    ADD CONSTRAINT finding_policy_evaluations_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES public.scan_attempts(id) ON DELETE SET NULL;


--
-- Name: finding_policy_evaluations finding_policy_evaluations_policy_version_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_policy_evaluations
    ADD CONSTRAINT finding_policy_evaluations_policy_version_id_fkey FOREIGN KEY (policy_version_id) REFERENCES public.finding_policy_versions(id) ON DELETE RESTRICT;


--
-- Name: finding_policy_evaluations finding_policy_evaluations_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_policy_evaluations
    ADD CONSTRAINT finding_policy_evaluations_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE SET NULL;


--
-- Name: finding_policy_evaluations finding_policy_evaluations_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_policy_evaluations
    ADD CONSTRAINT finding_policy_evaluations_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE SET NULL;


--
-- Name: finding_policy_evaluations finding_policy_evaluations_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_policy_evaluations
    ADD CONSTRAINT finding_policy_evaluations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: finding_policy_versions finding_policy_versions_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_policy_versions
    ADD CONSTRAINT finding_policy_versions_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: finding_policy_versions finding_policy_versions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_policy_versions
    ADD CONSTRAINT finding_policy_versions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: finding_waiver_events finding_waiver_events_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_waiver_events
    ADD CONSTRAINT finding_waiver_events_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: finding_waiver_events finding_waiver_events_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_waiver_events
    ADD CONSTRAINT finding_waiver_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: finding_waiver_events finding_waiver_events_waiver_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_waiver_events
    ADD CONSTRAINT finding_waiver_events_waiver_id_fkey FOREIGN KEY (waiver_id) REFERENCES public.finding_waivers(id) ON DELETE RESTRICT;


--
-- Name: finding_waivers finding_waivers_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_waivers
    ADD CONSTRAINT finding_waivers_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: finding_waivers finding_waivers_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_waivers
    ADD CONSTRAINT finding_waivers_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE SET NULL;


--
-- Name: finding_waivers finding_waivers_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_waivers
    ADD CONSTRAINT finding_waivers_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE SET NULL;


--
-- Name: finding_waivers finding_waivers_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_waivers
    ADD CONSTRAINT finding_waivers_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE SET NULL;


--
-- Name: finding_waivers finding_waivers_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_waivers
    ADD CONSTRAINT finding_waivers_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: findings findings_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id);


--
-- Name: approval_gates fk_approval_gates_actor; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approval_gates
    ADD CONSTRAINT fk_approval_gates_actor FOREIGN KEY (actor_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: approval_gates fk_approval_gates_attempt_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approval_gates
    ADD CONSTRAINT fk_approval_gates_attempt_id FOREIGN KEY (attempt_id) REFERENCES public.scan_attempts(id) ON DELETE SET NULL;


--
-- Name: approval_gates fk_approval_gates_scan; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approval_gates
    ADD CONSTRAINT fk_approval_gates_scan FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: auth_sessions fk_auth_sessions_active_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT fk_auth_sessions_active_tenant_id FOREIGN KEY (active_tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;


--
-- Name: auth_sessions fk_auth_sessions_provider_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT fk_auth_sessions_provider_id FOREIGN KEY (provider_id) REFERENCES public.sso_providers(id) ON DELETE SET NULL;


--
-- Name: auth_sessions fk_auth_sessions_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT fk_auth_sessions_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;


--
-- Name: auth_sessions fk_auth_sessions_user_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT fk_auth_sessions_user_id FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: chat_sessions fk_chat_sessions_llm_config_id_llm_configurations; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sessions
    ADD CONSTRAINT fk_chat_sessions_llm_config_id_llm_configurations FOREIGN KEY (llm_config_id) REFERENCES public.llm_configurations(id);


--
-- Name: chat_sessions fk_chat_sessions_project_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sessions
    ADD CONSTRAINT fk_chat_sessions_project_id FOREIGN KEY (project_id) REFERENCES public.projects(id);


--
-- Name: chat_sessions fk_chat_sessions_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sessions
    ADD CONSTRAINT fk_chat_sessions_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: findings fk_findings_coverage_entry_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT fk_findings_coverage_entry_id FOREIGN KEY (coverage_entry_id) REFERENCES public.scanner_coverage_entries(id) ON DELETE SET NULL;


--
-- Name: findings fk_findings_disposition_by; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT fk_findings_disposition_by FOREIGN KEY (disposition_by) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: findings fk_findings_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT fk_findings_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: llm_interactions fk_llm_interactions_llm_config_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_interactions
    ADD CONSTRAINT fk_llm_interactions_llm_config_id FOREIGN KEY (llm_config_id) REFERENCES public.llm_configurations(id) ON DELETE SET NULL;


--
-- Name: llm_interactions fk_llm_interactions_usage_event_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_interactions
    ADD CONSTRAINT fk_llm_interactions_usage_event_id FOREIGN KEY (usage_event_id) REFERENCES public.llm_usage_events(id) ON DELETE SET NULL;


--
-- Name: oauth_accounts fk_oauth_accounts_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_accounts
    ADD CONSTRAINT fk_oauth_accounts_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;


--
-- Name: projects fk_projects_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT fk_projects_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: saml_subjects fk_saml_subjects_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saml_subjects
    ADD CONSTRAINT fk_saml_subjects_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;


--
-- Name: scan_artifacts fk_scan_artifacts_attempt_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_artifacts
    ADD CONSTRAINT fk_scan_artifacts_attempt_id FOREIGN KEY (attempt_id) REFERENCES public.scan_attempts(id) ON DELETE CASCADE;


--
-- Name: scan_artifacts fk_scan_artifacts_evidence_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_artifacts
    ADD CONSTRAINT fk_scan_artifacts_evidence_id FOREIGN KEY (evidence_id) REFERENCES public.evidence_objects(id) ON DELETE SET NULL;


--
-- Name: scan_events fk_scan_events_attempt_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_events
    ADD CONSTRAINT fk_scan_events_attempt_id FOREIGN KEY (attempt_id) REFERENCES public.scan_attempts(id) ON DELETE SET NULL;


--
-- Name: scan_outbox fk_scan_outbox_attempt_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_outbox
    ADD CONSTRAINT fk_scan_outbox_attempt_id FOREIGN KEY (attempt_id) REFERENCES public.scan_attempts(id) ON DELETE SET NULL;


--
-- Name: scan_tasks fk_scan_tasks_attempt_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_tasks
    ADD CONSTRAINT fk_scan_tasks_attempt_id FOREIGN KEY (attempt_id) REFERENCES public.scan_attempts(id) ON DELETE CASCADE;


--
-- Name: scans fk_scans_current_attempt_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT fk_scans_current_attempt_id FOREIGN KEY (current_attempt_id) REFERENCES public.scan_attempts(id) ON DELETE SET NULL;


--
-- Name: scans fk_scans_reasoning_llm_config_id_llm_configurations; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT fk_scans_reasoning_llm_config_id_llm_configurations FOREIGN KEY (reasoning_llm_config_id) REFERENCES public.llm_configurations(id);


--
-- Name: scans fk_scans_secondary_reasoning_llm_config_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT fk_scans_secondary_reasoning_llm_config_id FOREIGN KEY (secondary_reasoning_llm_config_id) REFERENCES public.llm_configurations(id);


--
-- Name: scans fk_scans_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT fk_scans_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: scans fk_scans_utility_llm_config_id_llm_configurations; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT fk_scans_utility_llm_config_id_llm_configurations FOREIGN KEY (utility_llm_config_id) REFERENCES public.llm_configurations(id);


--
-- Name: scim_tokens fk_scim_tokens_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scim_tokens
    ADD CONSTRAINT fk_scim_tokens_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: sso_providers fk_sso_providers_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_providers
    ADD CONSTRAINT fk_sso_providers_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;


--
-- Name: user_groups fk_user_groups_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT fk_user_groups_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: user fk_user_tenant_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT fk_user_tenant_id FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: framework_agent_mappings framework_agent_mappings_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.framework_agent_mappings
    ADD CONSTRAINT framework_agent_mappings_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- Name: framework_agent_mappings framework_agent_mappings_framework_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.framework_agent_mappings
    ADD CONSTRAINT framework_agent_mappings_framework_id_fkey FOREIGN KEY (framework_id) REFERENCES public.frameworks(id);


--
-- Name: governance_legal_holds governance_legal_holds_placed_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_legal_holds
    ADD CONSTRAINT governance_legal_holds_placed_by_user_id_fkey FOREIGN KEY (placed_by_user_id) REFERENCES public."user"(id) ON DELETE RESTRICT;


--
-- Name: governance_legal_holds governance_legal_holds_released_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_legal_holds
    ADD CONSTRAINT governance_legal_holds_released_by_user_id_fkey FOREIGN KEY (released_by_user_id) REFERENCES public."user"(id) ON DELETE RESTRICT;


--
-- Name: governance_legal_holds governance_legal_holds_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_legal_holds
    ADD CONSTRAINT governance_legal_holds_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: governance_operations governance_operations_requested_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_operations
    ADD CONSTRAINT governance_operations_requested_by_user_id_fkey FOREIGN KEY (requested_by_user_id) REFERENCES public."user"(id) ON DELETE RESTRICT;


--
-- Name: governance_operations governance_operations_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_operations
    ADD CONSTRAINT governance_operations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: governance_store_actions governance_store_actions_operation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_store_actions
    ADD CONSTRAINT governance_store_actions_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES public.governance_operations(id) ON DELETE RESTRICT;


--
-- Name: governance_store_actions governance_store_actions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_store_actions
    ADD CONSTRAINT governance_store_actions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: integration_delivery_audit integration_delivery_audit_outbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_delivery_audit
    ADD CONSTRAINT integration_delivery_audit_outbox_id_fkey FOREIGN KEY (outbox_id) REFERENCES public.integration_outbox(id) ON DELETE RESTRICT;


--
-- Name: integration_delivery_audit integration_delivery_audit_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_delivery_audit
    ADD CONSTRAINT integration_delivery_audit_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES public.integration_service_principals(id) ON DELETE RESTRICT;


--
-- Name: integration_delivery_audit integration_delivery_audit_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_delivery_audit
    ADD CONSTRAINT integration_delivery_audit_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: integration_finding_tickets integration_finding_tickets_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_finding_tickets
    ADD CONSTRAINT integration_finding_tickets_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES public.integration_service_principals(id) ON DELETE RESTRICT;


--
-- Name: integration_finding_tickets integration_finding_tickets_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_finding_tickets
    ADD CONSTRAINT integration_finding_tickets_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: integration_grants integration_grants_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_grants
    ADD CONSTRAINT integration_grants_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES public.integration_service_principals(id) ON DELETE RESTRICT;


--
-- Name: integration_grants integration_grants_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_grants
    ADD CONSTRAINT integration_grants_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: integration_inbound_receipts integration_inbound_receipts_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_inbound_receipts
    ADD CONSTRAINT integration_inbound_receipts_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES public.integration_service_principals(id) ON DELETE RESTRICT;


--
-- Name: integration_inbound_receipts integration_inbound_receipts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_inbound_receipts
    ADD CONSTRAINT integration_inbound_receipts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: integration_outbox integration_outbox_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_outbox
    ADD CONSTRAINT integration_outbox_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES public.integration_service_principals(id) ON DELETE RESTRICT;


--
-- Name: integration_outbox integration_outbox_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_outbox
    ADD CONSTRAINT integration_outbox_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: integration_service_principals integration_service_principals_created_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_service_principals
    ADD CONSTRAINT integration_service_principals_created_by_user_id_fkey FOREIGN KEY (created_by_user_id) REFERENCES public."user"(id) ON DELETE RESTRICT;


--
-- Name: integration_service_principals integration_service_principals_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_service_principals
    ADD CONSTRAINT integration_service_principals_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: integration_source_submissions integration_source_submissions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_source_submissions
    ADD CONSTRAINT integration_source_submissions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: integration_ticket_history integration_ticket_history_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_ticket_history
    ADD CONSTRAINT integration_ticket_history_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: integration_ticket_history integration_ticket_history_ticket_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_ticket_history
    ADD CONSTRAINT integration_ticket_history_ticket_id_fkey FOREIGN KEY (ticket_id) REFERENCES public.integration_finding_tickets(id) ON DELETE RESTRICT;


--
-- Name: llm_call_reservations llm_call_reservations_attempt_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_call_reservations
    ADD CONSTRAINT llm_call_reservations_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES public.scan_attempts(id) ON DELETE SET NULL;


--
-- Name: llm_call_reservations llm_call_reservations_llm_config_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_call_reservations
    ADD CONSTRAINT llm_call_reservations_llm_config_id_fkey FOREIGN KEY (llm_config_id) REFERENCES public.llm_configurations(id) ON DELETE SET NULL;


--
-- Name: llm_call_reservations llm_call_reservations_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_call_reservations
    ADD CONSTRAINT llm_call_reservations_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE SET NULL;


--
-- Name: llm_call_reservations llm_call_reservations_usage_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_call_reservations
    ADD CONSTRAINT llm_call_reservations_usage_event_id_fkey FOREIGN KEY (usage_event_id) REFERENCES public.llm_usage_events(id) ON DELETE SET NULL;


--
-- Name: llm_interactions llm_interactions_chat_message_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_interactions
    ADD CONSTRAINT llm_interactions_chat_message_id_fkey FOREIGN KEY (chat_message_id) REFERENCES public.chat_messages(id);


--
-- Name: llm_interactions llm_interactions_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_interactions
    ADD CONSTRAINT llm_interactions_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id);


--
-- Name: llm_price_overrides llm_price_overrides_created_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_price_overrides
    ADD CONSTRAINT llm_price_overrides_created_by_user_id_fkey FOREIGN KEY (created_by_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: llm_price_overrides llm_price_overrides_llm_config_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_price_overrides
    ADD CONSTRAINT llm_price_overrides_llm_config_id_fkey FOREIGN KEY (llm_config_id) REFERENCES public.llm_configurations(id) ON DELETE CASCADE;


--
-- Name: llm_usage_events llm_usage_events_attempt_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage_events
    ADD CONSTRAINT llm_usage_events_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES public.scan_attempts(id) ON DELETE SET NULL;


--
-- Name: llm_usage_events llm_usage_events_chat_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage_events
    ADD CONSTRAINT llm_usage_events_chat_session_id_fkey FOREIGN KEY (chat_session_id) REFERENCES public.chat_sessions(id) ON DELETE SET NULL;


--
-- Name: llm_usage_events llm_usage_events_llm_config_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage_events
    ADD CONSTRAINT llm_usage_events_llm_config_id_fkey FOREIGN KEY (llm_config_id) REFERENCES public.llm_configurations(id) ON DELETE SET NULL;


--
-- Name: llm_usage_events llm_usage_events_rag_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage_events
    ADD CONSTRAINT llm_usage_events_rag_job_id_fkey FOREIGN KEY (rag_job_id) REFERENCES public.rag_preprocessing_jobs(id) ON DELETE SET NULL;


--
-- Name: llm_usage_events llm_usage_events_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage_events
    ADD CONSTRAINT llm_usage_events_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE SET NULL;


--
-- Name: llm_usage_events llm_usage_events_scan_task_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage_events
    ADD CONSTRAINT llm_usage_events_scan_task_id_fkey FOREIGN KEY (scan_task_id) REFERENCES public.scan_tasks(id) ON DELETE SET NULL;


--
-- Name: llm_usage_events llm_usage_events_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage_events
    ADD CONSTRAINT llm_usage_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: llm_usage_events llm_usage_events_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage_events
    ADD CONSTRAINT llm_usage_events_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: llm_usage_line_items llm_usage_line_items_usage_request_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage_line_items
    ADD CONSTRAINT llm_usage_line_items_usage_request_id_fkey FOREIGN KEY (usage_request_id) REFERENCES public.llm_usage_requests(id) ON DELETE CASCADE;


--
-- Name: llm_usage_requests llm_usage_requests_usage_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage_requests
    ADD CONSTRAINT llm_usage_requests_usage_event_id_fkey FOREIGN KEY (usage_event_id) REFERENCES public.llm_usage_events(id) ON DELETE CASCADE;


--
-- Name: oauth_accounts oauth_accounts_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_accounts
    ADD CONSTRAINT oauth_accounts_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.sso_providers(id) ON DELETE CASCADE;


--
-- Name: oauth_accounts oauth_accounts_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_accounts
    ADD CONSTRAINT oauth_accounts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: offline_bundle_deployments offline_bundle_deployments_previous_deployment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.offline_bundle_deployments
    ADD CONSTRAINT offline_bundle_deployments_previous_deployment_id_fkey FOREIGN KEY (previous_deployment_id) REFERENCES public.offline_bundle_deployments(id) ON DELETE RESTRICT;


--
-- Name: projects projects_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: provider_billing_connectors provider_billing_connectors_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_billing_connectors
    ADD CONSTRAINT provider_billing_connectors_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: provider_reconciliation_adjustments provider_reconciliation_adjustments_evidence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_reconciliation_adjustments
    ADD CONSTRAINT provider_reconciliation_adjustments_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES public.provider_reconciliation_evidence(id) ON DELETE RESTRICT;


--
-- Name: provider_reconciliation_adjustments provider_reconciliation_adjustments_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_reconciliation_adjustments
    ADD CONSTRAINT provider_reconciliation_adjustments_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.provider_reconciliation_runs(id) ON DELETE RESTRICT;


--
-- Name: provider_reconciliation_adjustments provider_reconciliation_adjustments_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_reconciliation_adjustments
    ADD CONSTRAINT provider_reconciliation_adjustments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: provider_reconciliation_alert_outbox provider_reconciliation_alert_outbox_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_reconciliation_alert_outbox
    ADD CONSTRAINT provider_reconciliation_alert_outbox_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.provider_reconciliation_runs(id) ON DELETE RESTRICT;


--
-- Name: provider_reconciliation_alert_outbox provider_reconciliation_alert_outbox_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_reconciliation_alert_outbox
    ADD CONSTRAINT provider_reconciliation_alert_outbox_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: provider_reconciliation_evidence provider_reconciliation_evidence_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_reconciliation_evidence
    ADD CONSTRAINT provider_reconciliation_evidence_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.provider_reconciliation_runs(id) ON DELETE RESTRICT;


--
-- Name: provider_reconciliation_evidence provider_reconciliation_evidence_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_reconciliation_evidence
    ADD CONSTRAINT provider_reconciliation_evidence_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: provider_reconciliation_runs provider_reconciliation_runs_connector_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_reconciliation_runs
    ADD CONSTRAINT provider_reconciliation_runs_connector_id_fkey FOREIGN KEY (connector_id) REFERENCES public.provider_billing_connectors(id) ON DELETE RESTRICT;


--
-- Name: provider_reconciliation_runs provider_reconciliation_runs_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_reconciliation_runs
    ADD CONSTRAINT provider_reconciliation_runs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: push_subscriptions push_subscriptions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_subscriptions
    ADD CONSTRAINT push_subscriptions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: rag_preprocessing_jobs rag_preprocessing_jobs_llm_config_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rag_preprocessing_jobs
    ADD CONSTRAINT rag_preprocessing_jobs_llm_config_id_fkey FOREIGN KEY (llm_config_id) REFERENCES public.llm_configurations(id);


--
-- Name: rag_preprocessing_jobs rag_preprocessing_jobs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rag_preprocessing_jobs
    ADD CONSTRAINT rag_preprocessing_jobs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: role_assignments role_assignments_created_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_assignments
    ADD CONSTRAINT role_assignments_created_by_user_id_fkey FOREIGN KEY (created_by_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: role_assignments role_assignments_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_assignments
    ADD CONSTRAINT role_assignments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: role_assignments role_assignments_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_assignments
    ADD CONSTRAINT role_assignments_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: rule_foundry_candidates rule_foundry_candidates_creator_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_candidates
    ADD CONSTRAINT rule_foundry_candidates_creator_user_id_fkey FOREIGN KEY (creator_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: rule_foundry_candidates rule_foundry_candidates_promoter_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_candidates
    ADD CONSTRAINT rule_foundry_candidates_promoter_user_id_fkey FOREIGN KEY (promoter_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: rule_foundry_candidates rule_foundry_candidates_reviewer_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_candidates
    ADD CONSTRAINT rule_foundry_candidates_reviewer_user_id_fkey FOREIGN KEY (reviewer_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: rule_foundry_candidates rule_foundry_candidates_source_attempt_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_candidates
    ADD CONSTRAINT rule_foundry_candidates_source_attempt_id_fkey FOREIGN KEY (source_attempt_id) REFERENCES public.scan_attempts(id) ON DELETE SET NULL;


--
-- Name: rule_foundry_candidates rule_foundry_candidates_source_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_candidates
    ADD CONSTRAINT rule_foundry_candidates_source_finding_id_fkey FOREIGN KEY (source_finding_id) REFERENCES public.findings(id) ON DELETE SET NULL;


--
-- Name: rule_foundry_candidates rule_foundry_candidates_source_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_candidates
    ADD CONSTRAINT rule_foundry_candidates_source_scan_id_fkey FOREIGN KEY (source_scan_id) REFERENCES public.scans(id) ON DELETE SET NULL;


--
-- Name: rule_foundry_candidates rule_foundry_candidates_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_candidates
    ADD CONSTRAINT rule_foundry_candidates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: rule_foundry_deployments rule_foundry_deployments_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_deployments
    ADD CONSTRAINT rule_foundry_deployments_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: rule_foundry_deployments rule_foundry_deployments_candidate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_deployments
    ADD CONSTRAINT rule_foundry_deployments_candidate_id_fkey FOREIGN KEY (candidate_id) REFERENCES public.rule_foundry_candidates(id) ON DELETE RESTRICT;


--
-- Name: rule_foundry_deployments rule_foundry_deployments_prior_version_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_deployments
    ADD CONSTRAINT rule_foundry_deployments_prior_version_id_fkey FOREIGN KEY (prior_version_id) REFERENCES public.rule_foundry_versions(id) ON DELETE RESTRICT;


--
-- Name: rule_foundry_deployments rule_foundry_deployments_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_deployments
    ADD CONSTRAINT rule_foundry_deployments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: rule_foundry_deployments rule_foundry_deployments_version_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_deployments
    ADD CONSTRAINT rule_foundry_deployments_version_id_fkey FOREIGN KEY (version_id) REFERENCES public.rule_foundry_versions(id) ON DELETE RESTRICT;


--
-- Name: rule_foundry_events rule_foundry_events_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_events
    ADD CONSTRAINT rule_foundry_events_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: rule_foundry_events rule_foundry_events_candidate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_events
    ADD CONSTRAINT rule_foundry_events_candidate_id_fkey FOREIGN KEY (candidate_id) REFERENCES public.rule_foundry_candidates(id) ON DELETE RESTRICT;


--
-- Name: rule_foundry_events rule_foundry_events_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_events
    ADD CONSTRAINT rule_foundry_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: rule_foundry_gitleaks_candidates rule_foundry_gitleaks_candidates_candidate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_gitleaks_candidates
    ADD CONSTRAINT rule_foundry_gitleaks_candidates_candidate_id_fkey FOREIGN KEY (candidate_id) REFERENCES public.rule_foundry_candidates(id) ON DELETE CASCADE;


--
-- Name: rule_foundry_gitleaks_candidates rule_foundry_gitleaks_candidates_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_gitleaks_candidates
    ADD CONSTRAINT rule_foundry_gitleaks_candidates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: rule_foundry_osv_candidates rule_foundry_osv_candidates_candidate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_osv_candidates
    ADD CONSTRAINT rule_foundry_osv_candidates_candidate_id_fkey FOREIGN KEY (candidate_id) REFERENCES public.rule_foundry_candidates(id) ON DELETE CASCADE;


--
-- Name: rule_foundry_osv_candidates rule_foundry_osv_candidates_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_osv_candidates
    ADD CONSTRAINT rule_foundry_osv_candidates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: rule_foundry_semgrep_candidates rule_foundry_semgrep_candidates_candidate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_semgrep_candidates
    ADD CONSTRAINT rule_foundry_semgrep_candidates_candidate_id_fkey FOREIGN KEY (candidate_id) REFERENCES public.rule_foundry_candidates(id) ON DELETE CASCADE;


--
-- Name: rule_foundry_semgrep_candidates rule_foundry_semgrep_candidates_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_semgrep_candidates
    ADD CONSTRAINT rule_foundry_semgrep_candidates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: rule_foundry_shadow_observations rule_foundry_shadow_observations_attempt_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_shadow_observations
    ADD CONSTRAINT rule_foundry_shadow_observations_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES public.scan_attempts(id) ON DELETE RESTRICT;


--
-- Name: rule_foundry_shadow_observations rule_foundry_shadow_observations_deployment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_shadow_observations
    ADD CONSTRAINT rule_foundry_shadow_observations_deployment_id_fkey FOREIGN KEY (deployment_id) REFERENCES public.rule_foundry_deployments(id) ON DELETE RESTRICT;


--
-- Name: rule_foundry_shadow_observations rule_foundry_shadow_observations_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_shadow_observations
    ADD CONSTRAINT rule_foundry_shadow_observations_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE RESTRICT;


--
-- Name: rule_foundry_shadow_observations rule_foundry_shadow_observations_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_shadow_observations
    ADD CONSTRAINT rule_foundry_shadow_observations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: rule_foundry_versions rule_foundry_versions_candidate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_versions
    ADD CONSTRAINT rule_foundry_versions_candidate_id_fkey FOREIGN KEY (candidate_id) REFERENCES public.rule_foundry_candidates(id) ON DELETE RESTRICT;


--
-- Name: rule_foundry_versions rule_foundry_versions_reviewer_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_versions
    ADD CONSTRAINT rule_foundry_versions_reviewer_user_id_fkey FOREIGN KEY (reviewer_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: rule_foundry_versions rule_foundry_versions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rule_foundry_versions
    ADD CONSTRAINT rule_foundry_versions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: saml_subjects saml_subjects_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saml_subjects
    ADD CONSTRAINT saml_subjects_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.sso_providers(id) ON DELETE CASCADE;


--
-- Name: saml_subjects saml_subjects_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saml_subjects
    ADD CONSTRAINT saml_subjects_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: scan_artifacts scan_artifacts_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_artifacts
    ADD CONSTRAINT scan_artifacts_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: scan_attempts scan_attempts_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_attempts
    ADD CONSTRAINT scan_attempts_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: scan_attempts scan_attempts_parent_attempt_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_attempts
    ADD CONSTRAINT scan_attempts_parent_attempt_id_fkey FOREIGN KEY (parent_attempt_id) REFERENCES public.scan_attempts(id) ON DELETE SET NULL;


--
-- Name: scan_attempts scan_attempts_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_attempts
    ADD CONSTRAINT scan_attempts_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: scan_attempts scan_attempts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_attempts
    ADD CONSTRAINT scan_attempts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: scan_events scan_events_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_events
    ADD CONSTRAINT scan_events_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id);


--
-- Name: scan_outbox scan_outbox_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_outbox
    ADD CONSTRAINT scan_outbox_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: scan_tasks scan_tasks_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_tasks
    ADD CONSTRAINT scan_tasks_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: scanner_coverage_entries scanner_coverage_entries_attempt_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scanner_coverage_entries
    ADD CONSTRAINT scanner_coverage_entries_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES public.scan_attempts(id) ON DELETE CASCADE;


--
-- Name: scanner_coverage_entries scanner_coverage_entries_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scanner_coverage_entries
    ADD CONSTRAINT scanner_coverage_entries_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: scanner_coverage_entries scanner_coverage_entries_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scanner_coverage_entries
    ADD CONSTRAINT scanner_coverage_entries_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: scanner_coverage_policy_decisions scanner_coverage_policy_decisions_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scanner_coverage_policy_decisions
    ADD CONSTRAINT scanner_coverage_policy_decisions_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: scanner_coverage_policy_decisions scanner_coverage_policy_decisions_attempt_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scanner_coverage_policy_decisions
    ADD CONSTRAINT scanner_coverage_policy_decisions_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES public.scan_attempts(id) ON DELETE CASCADE;


--
-- Name: scanner_coverage_policy_decisions scanner_coverage_policy_decisions_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scanner_coverage_policy_decisions
    ADD CONSTRAINT scanner_coverage_policy_decisions_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: scanner_coverage_policy_decisions scanner_coverage_policy_decisions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scanner_coverage_policy_decisions
    ADD CONSTRAINT scanner_coverage_policy_decisions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: scans scans_parent_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_parent_scan_id_fkey FOREIGN KEY (parent_scan_id) REFERENCES public.scans(id);


--
-- Name: scans scans_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id);


--
-- Name: scans scans_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: scim_tokens scim_tokens_created_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scim_tokens
    ADD CONSTRAINT scim_tokens_created_by_user_id_fkey FOREIGN KEY (created_by_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: semgrep_rules semgrep_rules_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.semgrep_rules
    ADD CONSTRAINT semgrep_rules_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.semgrep_rule_sources(id) ON DELETE CASCADE;


--
-- Name: semgrep_sync_runs semgrep_sync_runs_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.semgrep_sync_runs
    ADD CONSTRAINT semgrep_sync_runs_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.semgrep_rule_sources(id) ON DELETE CASCADE;


--
-- Name: tenant_retention_policies tenant_retention_policies_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_retention_policies
    ADD CONSTRAINT tenant_retention_policies_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: tenant_retention_policies tenant_retention_policies_updated_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_retention_policies
    ADD CONSTRAINT tenant_retention_policies_updated_by_user_id_fkey FOREIGN KEY (updated_by_user_id) REFERENCES public."user"(id) ON DELETE RESTRICT;


--
-- Name: tenant_verified_domains tenant_verified_domains_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_verified_domains
    ADD CONSTRAINT tenant_verified_domains_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: usage_budget_allocations usage_budget_allocations_counter_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_allocations
    ADD CONSTRAINT usage_budget_allocations_counter_id_fkey FOREIGN KEY (counter_id) REFERENCES public.usage_budget_counters(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_allocations usage_budget_allocations_reservation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_allocations
    ADD CONSTRAINT usage_budget_allocations_reservation_id_fkey FOREIGN KEY (reservation_id) REFERENCES public.usage_budget_reservations(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_allocations usage_budget_allocations_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_allocations
    ADD CONSTRAINT usage_budget_allocations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_counters usage_budget_counters_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_counters
    ADD CONSTRAINT usage_budget_counters_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.usage_budget_policies(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_counters usage_budget_counters_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_counters
    ADD CONSTRAINT usage_budget_counters_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_notification_outbox usage_budget_notification_outbox_recipient_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_notification_outbox
    ADD CONSTRAINT usage_budget_notification_outbox_recipient_user_id_fkey FOREIGN KEY (recipient_user_id) REFERENCES public."user"(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_notification_outbox usage_budget_notification_outbox_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_notification_outbox
    ADD CONSTRAINT usage_budget_notification_outbox_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_notification_outbox usage_budget_notification_outbox_threshold_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_notification_outbox
    ADD CONSTRAINT usage_budget_notification_outbox_threshold_event_id_fkey FOREIGN KEY (threshold_event_id) REFERENCES public.usage_budget_threshold_events(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_overrides usage_budget_overrides_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_overrides
    ADD CONSTRAINT usage_budget_overrides_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.usage_budget_policies(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_overrides usage_budget_overrides_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_overrides
    ADD CONSTRAINT usage_budget_overrides_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_policies usage_budget_policies_llm_config_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_policies
    ADD CONSTRAINT usage_budget_policies_llm_config_id_fkey FOREIGN KEY (llm_config_id) REFERENCES public.llm_configurations(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_policies usage_budget_policies_target_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_policies
    ADD CONSTRAINT usage_budget_policies_target_group_id_fkey FOREIGN KEY (target_group_id) REFERENCES public.user_groups(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_policies usage_budget_policies_target_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_policies
    ADD CONSTRAINT usage_budget_policies_target_user_id_fkey FOREIGN KEY (target_user_id) REFERENCES public."user"(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_policies usage_budget_policies_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_policies
    ADD CONSTRAINT usage_budget_policies_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_reservations usage_budget_reservations_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_reservations
    ADD CONSTRAINT usage_budget_reservations_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: usage_budget_reservations usage_budget_reservations_llm_config_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_reservations
    ADD CONSTRAINT usage_budget_reservations_llm_config_id_fkey FOREIGN KEY (llm_config_id) REFERENCES public.llm_configurations(id) ON DELETE SET NULL;


--
-- Name: usage_budget_reservations usage_budget_reservations_parent_reservation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_reservations
    ADD CONSTRAINT usage_budget_reservations_parent_reservation_id_fkey FOREIGN KEY (parent_reservation_id) REFERENCES public.usage_budget_reservations(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_reservations usage_budget_reservations_scan_attempt_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_reservations
    ADD CONSTRAINT usage_budget_reservations_scan_attempt_id_fkey FOREIGN KEY (scan_attempt_id) REFERENCES public.scan_attempts(id) ON DELETE SET NULL;


--
-- Name: usage_budget_reservations usage_budget_reservations_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_reservations
    ADD CONSTRAINT usage_budget_reservations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_settlements usage_budget_settlements_reservation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_settlements
    ADD CONSTRAINT usage_budget_settlements_reservation_id_fkey FOREIGN KEY (reservation_id) REFERENCES public.usage_budget_reservations(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_settlements usage_budget_settlements_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_settlements
    ADD CONSTRAINT usage_budget_settlements_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_settlements usage_budget_settlements_usage_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_settlements
    ADD CONSTRAINT usage_budget_settlements_usage_event_id_fkey FOREIGN KEY (usage_event_id) REFERENCES public.llm_usage_events(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_threshold_events usage_budget_threshold_events_counter_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_threshold_events
    ADD CONSTRAINT usage_budget_threshold_events_counter_id_fkey FOREIGN KEY (counter_id) REFERENCES public.usage_budget_counters(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_threshold_events usage_budget_threshold_events_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_threshold_events
    ADD CONSTRAINT usage_budget_threshold_events_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.usage_budget_policies(id) ON DELETE RESTRICT;


--
-- Name: usage_budget_threshold_events usage_budget_threshold_events_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_budget_threshold_events
    ADD CONSTRAINT usage_budget_threshold_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: user_group_memberships user_group_memberships_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_group_memberships
    ADD CONSTRAINT user_group_memberships_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.user_groups(id) ON DELETE CASCADE;


--
-- Name: user_group_memberships user_group_memberships_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_group_memberships
    ADD CONSTRAINT user_group_memberships_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: user_groups user_groups_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: webauthn_credentials webauthn_credentials_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


-- Required bootstrap identity. Runtime tenant defaults and first-user setup
-- depend on this row existing before tenant RLS is enabled.
INSERT INTO public.tenants (id, slug, display_name)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'default',
    'Default Tenant'
)
ON CONFLICT (id) DO NOTHING;


--
-- Name: approval_gates; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.approval_gates ENABLE ROW LEVEL SECURITY;

--
-- Name: authorization_action_requests; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.authorization_action_requests ENABLE ROW LEVEL SECURITY;

--
-- Name: chat_messages; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.chat_messages ENABLE ROW LEVEL SECURITY;

--
-- Name: chat_sessions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.chat_sessions ENABLE ROW LEVEL SECURITY;

--
-- Name: code_snapshots; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.code_snapshots ENABLE ROW LEVEL SECURITY;

--
-- Name: evidence_deletion_outbox; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.evidence_deletion_outbox ENABLE ROW LEVEL SECURITY;

--
-- Name: evidence_governance_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.evidence_governance_events ENABLE ROW LEVEL SECURITY;

--
-- Name: evidence_manifests; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.evidence_manifests ENABLE ROW LEVEL SECURITY;

--
-- Name: evidence_objects; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.evidence_objects ENABLE ROW LEVEL SECURITY;

--
-- Name: finding_disposition_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.finding_disposition_events ENABLE ROW LEVEL SECURITY;

--
-- Name: finding_fix_candidates; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.finding_fix_candidates ENABLE ROW LEVEL SECURITY;

--
-- Name: finding_lineage_records; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.finding_lineage_records ENABLE ROW LEVEL SECURITY;

--
-- Name: finding_policy_evaluations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.finding_policy_evaluations ENABLE ROW LEVEL SECURITY;

--
-- Name: finding_policy_versions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.finding_policy_versions ENABLE ROW LEVEL SECURITY;

--
-- Name: finding_waiver_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.finding_waiver_events ENABLE ROW LEVEL SECURITY;

--
-- Name: finding_waivers; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.finding_waivers ENABLE ROW LEVEL SECURITY;

--
-- Name: findings; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;

--
-- Name: governance_legal_holds; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.governance_legal_holds ENABLE ROW LEVEL SECURITY;

--
-- Name: governance_operations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.governance_operations ENABLE ROW LEVEL SECURITY;

--
-- Name: governance_store_actions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.governance_store_actions ENABLE ROW LEVEL SECURITY;

--
-- Name: integration_delivery_audit; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.integration_delivery_audit ENABLE ROW LEVEL SECURITY;

--
-- Name: integration_finding_tickets; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.integration_finding_tickets ENABLE ROW LEVEL SECURITY;

--
-- Name: integration_grants; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.integration_grants ENABLE ROW LEVEL SECURITY;

--
-- Name: integration_inbound_receipts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.integration_inbound_receipts ENABLE ROW LEVEL SECURITY;

--
-- Name: integration_outbox; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.integration_outbox ENABLE ROW LEVEL SECURITY;

--
-- Name: integration_service_principals; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.integration_service_principals ENABLE ROW LEVEL SECURITY;

--
-- Name: integration_source_submissions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.integration_source_submissions ENABLE ROW LEVEL SECURITY;

--
-- Name: integration_ticket_history; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.integration_ticket_history ENABLE ROW LEVEL SECURITY;

--
-- Name: llm_call_reservations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.llm_call_reservations ENABLE ROW LEVEL SECURITY;

--
-- Name: llm_interactions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.llm_interactions ENABLE ROW LEVEL SECURITY;

--
-- Name: llm_usage_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.llm_usage_events ENABLE ROW LEVEL SECURITY;

--
-- Name: llm_usage_line_items; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.llm_usage_line_items ENABLE ROW LEVEL SECURITY;

--
-- Name: llm_usage_requests; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.llm_usage_requests ENABLE ROW LEVEL SECURITY;

--
-- Name: projects; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;

--
-- Name: provider_billing_connectors; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.provider_billing_connectors ENABLE ROW LEVEL SECURITY;

--
-- Name: provider_reconciliation_adjustments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.provider_reconciliation_adjustments ENABLE ROW LEVEL SECURITY;

--
-- Name: provider_reconciliation_alert_outbox; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.provider_reconciliation_alert_outbox ENABLE ROW LEVEL SECURITY;

--
-- Name: provider_reconciliation_evidence; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.provider_reconciliation_evidence ENABLE ROW LEVEL SECURITY;

--
-- Name: provider_reconciliation_runs; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.provider_reconciliation_runs ENABLE ROW LEVEL SECURITY;

--
-- Name: push_subscriptions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.push_subscriptions ENABLE ROW LEVEL SECURITY;

--
-- Name: rag_preprocessing_jobs; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.rag_preprocessing_jobs ENABLE ROW LEVEL SECURITY;

--
-- Name: role_assignments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.role_assignments ENABLE ROW LEVEL SECURITY;

--
-- Name: rule_foundry_candidates; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.rule_foundry_candidates ENABLE ROW LEVEL SECURITY;

--
-- Name: rule_foundry_deployments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.rule_foundry_deployments ENABLE ROW LEVEL SECURITY;

--
-- Name: rule_foundry_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.rule_foundry_events ENABLE ROW LEVEL SECURITY;

--
-- Name: rule_foundry_gitleaks_candidates; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.rule_foundry_gitleaks_candidates ENABLE ROW LEVEL SECURITY;

--
-- Name: rule_foundry_osv_candidates; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.rule_foundry_osv_candidates ENABLE ROW LEVEL SECURITY;

--
-- Name: rule_foundry_semgrep_candidates; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.rule_foundry_semgrep_candidates ENABLE ROW LEVEL SECURITY;

--
-- Name: rule_foundry_shadow_observations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.rule_foundry_shadow_observations ENABLE ROW LEVEL SECURITY;

--
-- Name: rule_foundry_versions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.rule_foundry_versions ENABLE ROW LEVEL SECURITY;

--
-- Name: scan_artifacts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scan_artifacts ENABLE ROW LEVEL SECURITY;

--
-- Name: scan_attempts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scan_attempts ENABLE ROW LEVEL SECURITY;

--
-- Name: scan_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scan_events ENABLE ROW LEVEL SECURITY;

--
-- Name: scan_outbox; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scan_outbox ENABLE ROW LEVEL SECURITY;

--
-- Name: scan_tasks; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scan_tasks ENABLE ROW LEVEL SECURITY;

--
-- Name: scanner_coverage_entries; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scanner_coverage_entries ENABLE ROW LEVEL SECURITY;

--
-- Name: scanner_coverage_policy_decisions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scanner_coverage_policy_decisions ENABLE ROW LEVEL SECURITY;

--
-- Name: scans; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;

--
-- Name: approval_gates sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.approval_gates USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = approval_gates.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = approval_gates.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: authorization_action_requests sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.authorization_action_requests USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: chat_messages sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.chat_messages USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.chat_sessions c
  WHERE ((c.id = chat_messages.session_id) AND (c.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.chat_sessions c
  WHERE ((c.id = chat_messages.session_id) AND (c.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: chat_sessions sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.chat_sessions USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: code_snapshots sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.code_snapshots USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = code_snapshots.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = code_snapshots.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: evidence_deletion_outbox sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.evidence_deletion_outbox USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.evidence_objects e
  WHERE ((e.id = evidence_deletion_outbox.evidence_id) AND (e.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.evidence_objects e
  WHERE ((e.id = evidence_deletion_outbox.evidence_id) AND (e.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: evidence_governance_events sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.evidence_governance_events USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: evidence_manifests sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.evidence_manifests USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = evidence_manifests.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = evidence_manifests.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: evidence_objects sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.evidence_objects USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: finding_disposition_events sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.finding_disposition_events USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.findings f
  WHERE ((f.id = finding_disposition_events.finding_id) AND (f.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.findings f
  WHERE ((f.id = finding_disposition_events.finding_id) AND (f.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: finding_fix_candidates sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.finding_fix_candidates USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = finding_fix_candidates.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = finding_fix_candidates.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: finding_lineage_records sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.finding_lineage_records USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: finding_policy_evaluations sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.finding_policy_evaluations USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: finding_policy_versions sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.finding_policy_versions USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: finding_waiver_events sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.finding_waiver_events USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: finding_waivers sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.finding_waivers USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: findings sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.findings USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: governance_legal_holds sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.governance_legal_holds USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: governance_operations sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.governance_operations USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: governance_store_actions sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.governance_store_actions USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: integration_delivery_audit sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.integration_delivery_audit USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: integration_finding_tickets sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.integration_finding_tickets USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: integration_grants sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.integration_grants USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: integration_inbound_receipts sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.integration_inbound_receipts USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: integration_outbox sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.integration_outbox USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: integration_service_principals sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.integration_service_principals USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: integration_source_submissions sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.integration_source_submissions USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: integration_ticket_history sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.integration_ticket_history USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: llm_call_reservations sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.llm_call_reservations USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = llm_call_reservations.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id())))) OR (EXISTS ( SELECT 1
   FROM public.llm_usage_events e
  WHERE ((e.id = llm_call_reservations.usage_event_id) AND (e.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = llm_call_reservations.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id())))) OR (EXISTS ( SELECT 1
   FROM public.llm_usage_events e
  WHERE ((e.id = llm_call_reservations.usage_event_id) AND (e.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: llm_interactions sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.llm_interactions USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = llm_interactions.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id())))) OR (EXISTS ( SELECT 1
   FROM (public.chat_messages m
     JOIN public.chat_sessions c ON ((c.id = m.session_id)))
  WHERE ((m.id = llm_interactions.chat_message_id) AND (c.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = llm_interactions.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id())))) OR (EXISTS ( SELECT 1
   FROM (public.chat_messages m
     JOIN public.chat_sessions c ON ((c.id = m.session_id)))
  WHERE ((m.id = llm_interactions.chat_message_id) AND (c.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: llm_usage_events sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.llm_usage_events USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: llm_usage_line_items sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.llm_usage_line_items USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM (public.llm_usage_requests r
     JOIN public.llm_usage_events e ON ((e.id = r.usage_event_id)))
  WHERE ((r.id = llm_usage_line_items.usage_request_id) AND (e.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM (public.llm_usage_requests r
     JOIN public.llm_usage_events e ON ((e.id = r.usage_event_id)))
  WHERE ((r.id = llm_usage_line_items.usage_request_id) AND (e.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: llm_usage_requests sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.llm_usage_requests USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.llm_usage_events e
  WHERE ((e.id = llm_usage_requests.usage_event_id) AND (e.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.llm_usage_events e
  WHERE ((e.id = llm_usage_requests.usage_event_id) AND (e.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: projects sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.projects USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: provider_billing_connectors sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.provider_billing_connectors USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: provider_reconciliation_adjustments sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.provider_reconciliation_adjustments USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: provider_reconciliation_alert_outbox sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.provider_reconciliation_alert_outbox USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: provider_reconciliation_evidence sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.provider_reconciliation_evidence USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: provider_reconciliation_runs sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.provider_reconciliation_runs USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: push_subscriptions sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.push_subscriptions USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public."user" u
  WHERE ((u.id = push_subscriptions.user_id) AND (u.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public."user" u
  WHERE ((u.id = push_subscriptions.user_id) AND (u.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: rag_preprocessing_jobs sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.rag_preprocessing_jobs USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public."user" u
  WHERE ((u.id = rag_preprocessing_jobs.user_id) AND (u.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public."user" u
  WHERE ((u.id = rag_preprocessing_jobs.user_id) AND (u.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: role_assignments sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.role_assignments USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()) OR ((tenant_id IS NULL) AND ((user_id)::text = current_setting('app.principal_id'::text, true))))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()) OR ((tenant_id IS NULL) AND ((user_id)::text = current_setting('app.principal_id'::text, true)))));


--
-- Name: rule_foundry_candidates sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.rule_foundry_candidates USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: rule_foundry_deployments sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.rule_foundry_deployments USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: rule_foundry_events sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.rule_foundry_events USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: rule_foundry_gitleaks_candidates sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.rule_foundry_gitleaks_candidates USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: rule_foundry_osv_candidates sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.rule_foundry_osv_candidates USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: rule_foundry_semgrep_candidates sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.rule_foundry_semgrep_candidates USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: rule_foundry_shadow_observations sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.rule_foundry_shadow_observations USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: rule_foundry_versions sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.rule_foundry_versions USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: scan_artifacts sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.scan_artifacts USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = scan_artifacts.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = scan_artifacts.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: scan_attempts sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.scan_attempts USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: scan_events sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.scan_events USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = scan_events.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = scan_events.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: scan_outbox sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.scan_outbox USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = scan_outbox.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = scan_outbox.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: scan_tasks sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.scan_tasks USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = scan_tasks.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.scans s
  WHERE ((s.id = scan_tasks.scan_id) AND (s.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: scanner_coverage_entries sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.scanner_coverage_entries USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: scanner_coverage_policy_decisions sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.scanner_coverage_policy_decisions USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: scans sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.scans USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: scim_tokens sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.scim_tokens USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: tenant_retention_policies sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.tenant_retention_policies USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: usage_budget_allocations sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.usage_budget_allocations USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: usage_budget_counters sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.usage_budget_counters USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: usage_budget_notification_outbox sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.usage_budget_notification_outbox USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: usage_budget_overrides sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.usage_budget_overrides USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: usage_budget_policies sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.usage_budget_policies USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: usage_budget_reservations sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.usage_budget_reservations USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: usage_budget_settlements sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.usage_budget_settlements USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: usage_budget_threshold_events sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.usage_budget_threshold_events USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: user_group_memberships sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.user_group_memberships USING ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.user_groups g
  WHERE ((g.id = user_group_memberships.group_id) AND (g.tenant_id = public.sccap_current_tenant_id())))))) WITH CHECK ((public.sccap_has_system_scope() OR (EXISTS ( SELECT 1
   FROM public.user_groups g
  WHERE ((g.id = user_group_memberships.group_id) AND (g.tenant_id = public.sccap_current_tenant_id()))))));


--
-- Name: user_groups sccap_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sccap_tenant_isolation ON public.user_groups USING ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id()))) WITH CHECK ((public.sccap_has_system_scope() OR (tenant_id = public.sccap_current_tenant_id())));


--
-- Name: scim_tokens; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scim_tokens ENABLE ROW LEVEL SECURITY;

--
-- Name: tenant_retention_policies; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tenant_retention_policies ENABLE ROW LEVEL SECURITY;

--
-- Name: usage_budget_allocations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.usage_budget_allocations ENABLE ROW LEVEL SECURITY;

--
-- Name: usage_budget_counters; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.usage_budget_counters ENABLE ROW LEVEL SECURITY;

--
-- Name: usage_budget_notification_outbox; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.usage_budget_notification_outbox ENABLE ROW LEVEL SECURITY;

--
-- Name: usage_budget_overrides; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.usage_budget_overrides ENABLE ROW LEVEL SECURITY;

--
-- Name: usage_budget_policies; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.usage_budget_policies ENABLE ROW LEVEL SECURITY;

--
-- Name: usage_budget_reservations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.usage_budget_reservations ENABLE ROW LEVEL SECURITY;

--
-- Name: usage_budget_settlements; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.usage_budget_settlements ENABLE ROW LEVEL SECURITY;

--
-- Name: usage_budget_threshold_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.usage_budget_threshold_events ENABLE ROW LEVEL SECURITY;

--
-- Name: user_group_memberships; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_group_memberships ENABLE ROW LEVEL SECURITY;

--
-- Name: user_groups; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_groups ENABLE ROW LEVEL SECURITY;

GRANT USAGE ON SCHEMA public TO sccap_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sccap_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sccap_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sccap_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO sccap_runtime;

-- pg_dump empties search_path while applying qualified schema objects. Alembic
-- writes its unqualified version table after upgrade() returns.
SET search_path = public;
