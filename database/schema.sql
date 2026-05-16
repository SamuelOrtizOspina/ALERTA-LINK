-- =========================================================
-- ALERTA-LINK - Esquema relacional PostgreSQL
-- =========================================================
-- Universidad Manuela Beltran - Ingenieria de Software 2025
-- Autores: Cristian Salazar, Samuel Ortiz Ospina, Juan Stiven Castro
--
-- Descripcion:
--   Script completo de creacion del esquema relacional del
--   sistema ALERTA-LINK para deteccion forense de URLs de
--   phishing/smishing. Compatible con PostgreSQL 13+.
--
-- Uso:
--   psql -U <usuario> -d alertalink -f database/schema.sql
--
-- Tablas:
--   1. urls               - Tabla maestra de URLs (dimensional)
--   2. ingested_urls      - URLs ingresadas al dataset
--   3. reports            - Reportes de usuarios desde la app
--   4. analysis_results   - Resultados de analisis de URLs
--   5. analysis_signals   - Senales detectadas (desnormalizado)
--   6. system_settings    - Configuracion persistente
--
-- Funciones / Triggers:
--   - fill_url_dimension()    Mantiene la tabla maestra urls
--   - sync_analysis_signals() Sincroniza signals JSONB -> tabla
-- =========================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =========================================================
-- 1) Tabla maestra de URLs
-- =========================================================
CREATE TABLE urls (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_normalized  TEXT NOT NULL,
    url_hash        CHAR(64) NOT NULL UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_urls_hash_len CHECK (char_length(url_hash) = 64)
);

CREATE INDEX idx_urls_created_at ON urls (created_at DESC);

-- =========================================================
-- 2) Funcion para sincronizar la dimension de URLs
--    Permite mantener compatibilidad con el codigo actual,
--    que sigue escribiendo url_normalized y url_hash
-- =========================================================
CREATE OR REPLACE FUNCTION fill_url_dimension()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_url_hash TEXT;
    v_url_id   UUID;
BEGIN
    IF NEW.url_normalized IS NULL OR btrim(NEW.url_normalized) = '' THEN
        RAISE EXCEPTION 'url_normalized no puede ser nulo o vacio';
    END IF;

    v_url_hash := COALESCE(
        NULLIF(NEW.url_hash, ''),
        encode(digest(NEW.url_normalized, 'sha256'), 'hex')
    );

    INSERT INTO urls (url_normalized, url_hash)
    VALUES (NEW.url_normalized, v_url_hash)
    ON CONFLICT (url_hash)
    DO UPDATE SET url_normalized = EXCLUDED.url_normalized
    RETURNING id INTO v_url_id;

    NEW.url_hash := v_url_hash;
    NEW.url_id := v_url_id;

    RETURN NEW;
END;
$$;

-- =========================================================
-- 3) ingested_urls
--    Compatible con el backend actual + FK relacional
-- =========================================================
CREATE TABLE ingested_urls (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_id          UUID NOT NULL REFERENCES urls(id) ON DELETE RESTRICT,
    url_normalized  TEXT NOT NULL,
    url_hash        CHAR(64) NOT NULL,
    label           SMALLINT NULL,
    source          TEXT NOT NULL DEFAULT 'manual',
    raw_payload     JSONB NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT ck_ingested_label
        CHECK (label IS NULL OR label IN (0, 1)),

    CONSTRAINT ck_ingested_source
        CHECK (source IN ('manual', 'feed', 'user', 'api')),

    CONSTRAINT ck_ingested_hash_len
        CHECK (char_length(url_hash) = 64)
);

CREATE INDEX idx_ingested_created_at ON ingested_urls (created_at DESC);
CREATE INDEX idx_ingested_label ON ingested_urls (label);
CREATE INDEX idx_ingested_source ON ingested_urls (source);
CREATE INDEX idx_ingested_url_hash ON ingested_urls (url_hash);
CREATE INDEX idx_ingested_url_id ON ingested_urls (url_id);
CREATE INDEX idx_ingested_raw_payload_gin ON ingested_urls USING GIN (raw_payload);

CREATE TRIGGER trg_ingested_fill_url_dimension
BEFORE INSERT OR UPDATE OF url_normalized, url_hash
ON ingested_urls
FOR EACH ROW
EXECUTE FUNCTION fill_url_dimension();

-- =========================================================
-- 4) reports
--    Compatible con el backend actual + FK relacional
-- =========================================================
CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_id          UUID NOT NULL REFERENCES urls(id) ON DELETE RESTRICT,
    url_normalized  TEXT NOT NULL,
    url_hash        CHAR(64) NOT NULL,
    label           TEXT NOT NULL,
    comment         TEXT NULL,
    contact         TEXT NULL,
    source          TEXT NOT NULL DEFAULT 'mobile_app',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT ck_reports_label
        CHECK (label IN ('phishing', 'malware', 'scam', 'unknown')),

    CONSTRAINT ck_reports_source
        CHECK (source IN ('mobile_app', 'web', 'api')),

    CONSTRAINT ck_reports_hash_len
        CHECK (char_length(url_hash) = 64)
);

CREATE INDEX idx_reports_created_at ON reports (created_at DESC);
CREATE INDEX idx_reports_label ON reports (label);
CREATE INDEX idx_reports_source ON reports (source);
CREATE INDEX idx_reports_url_hash ON reports (url_hash);
CREATE INDEX idx_reports_url_id ON reports (url_id);

CREATE TRIGGER trg_reports_fill_url_dimension
BEFORE INSERT OR UPDATE OF url_normalized, url_hash
ON reports
FOR EACH ROW
EXECUTE FUNCTION fill_url_dimension();

-- =========================================================
-- 5) analysis_results
--    Compatible con el modelo actual, pero extendida para:
--    - model_used
--    - probability
--    - recommendations
--    - crawler
-- =========================================================
CREATE TABLE analysis_results (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_id                   UUID NOT NULL REFERENCES urls(id) ON DELETE RESTRICT,
    url_normalized           TEXT NOT NULL,
    url_hash                 CHAR(64) NOT NULL,

    score                    INTEGER NOT NULL,
    risk_level               TEXT NOT NULL,
    signals                  JSONB NOT NULL DEFAULT '[]'::jsonb,

    ml_score                 INTEGER NULL,
    heuristic_score          INTEGER NULL,
    probability              NUMERIC(5,4) NULL,

    tranco_verified          BOOLEAN NOT NULL DEFAULT FALSE,
    tranco_rank              INTEGER NULL,
    virustotal_checked       BOOLEAN NOT NULL DEFAULT FALSE,
    virustotal_detections    INTEGER NULL,

    model_used               TEXT NULL,
    mode_used                TEXT NOT NULL DEFAULT 'auto',
    duration_ms              INTEGER NULL,

    recommendations          JSONB NOT NULL DEFAULT '[]'::jsonb,

    crawl_enabled            BOOLEAN NOT NULL DEFAULT FALSE,
    crawl_status             TEXT NOT NULL DEFAULT 'SKIPPED',
    crawl_final_url          TEXT NULL,
    crawl_redirect_chain     JSONB NOT NULL DEFAULT '[]'::jsonb,
    crawl_html_fingerprint   TEXT NULL,
    crawl_evidence           JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT ck_analysis_score_range
        CHECK (score >= 0 AND score <= 100),

    CONSTRAINT ck_analysis_ml_score_range
        CHECK (ml_score IS NULL OR (ml_score >= 0 AND ml_score <= 100)),

    CONSTRAINT ck_analysis_heuristic_score_range
        CHECK (heuristic_score IS NULL OR (heuristic_score >= 0 AND heuristic_score <= 100)),

    CONSTRAINT ck_analysis_probability_range
        CHECK (probability IS NULL OR (probability >= 0 AND probability <= 1)),

    -- OJO: aqui si incluyo SAFE, porque el repo lo usa
    CONSTRAINT ck_analysis_risk_level
        CHECK (risk_level IN ('SAFE', 'LOW', 'MEDIUM', 'HIGH')),

    CONSTRAINT ck_analysis_mode
        CHECK (mode_used IN ('online', 'offline', 'auto')),

    CONSTRAINT ck_analysis_model_used
        CHECK (model_used IS NULL OR model_used IN ('ml', 'heuristic')),

    CONSTRAINT ck_analysis_crawl_status
        CHECK (crawl_status IN ('SKIPPED', 'OK', 'TIMEOUT', 'ERROR')),

    CONSTRAINT ck_analysis_hash_len
        CHECK (char_length(url_hash) = 64)
);

CREATE INDEX idx_analysis_created_at ON analysis_results (created_at DESC);
CREATE INDEX idx_analysis_score ON analysis_results (score);
CREATE INDEX idx_analysis_risk_level ON analysis_results (risk_level);
CREATE INDEX idx_analysis_model_used ON analysis_results (model_used);
CREATE INDEX idx_analysis_mode_used ON analysis_results (mode_used);
CREATE INDEX idx_analysis_url_hash ON analysis_results (url_hash);
CREATE INDEX idx_analysis_url_id ON analysis_results (url_id);
CREATE INDEX idx_analysis_signals_gin ON analysis_results USING GIN (signals);
CREATE INDEX idx_analysis_recommendations_gin ON analysis_results USING GIN (recommendations);
CREATE INDEX idx_analysis_crawl_evidence_gin ON analysis_results USING GIN (crawl_evidence);

CREATE TRIGGER trg_analysis_fill_url_dimension
BEFORE INSERT OR UPDATE OF url_normalized, url_hash
ON analysis_results
FOR EACH ROW
EXECUTE FUNCTION fill_url_dimension();

-- =========================================================
-- 6) analysis_signals
--    Tabla relacional para explotar las senales sin depender
--    solo del JSONB
-- =========================================================
CREATE TABLE analysis_signals (
    id            BIGSERIAL PRIMARY KEY,
    analysis_id   UUID NOT NULL REFERENCES analysis_results(id) ON DELETE CASCADE,
    signal_code   TEXT NOT NULL,
    severity      TEXT NOT NULL,
    weight        INTEGER NOT NULL DEFAULT 0,
    explanation   TEXT NOT NULL,
    evidence      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT ck_signal_severity
        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH'))
);

CREATE INDEX idx_analysis_signals_analysis_id ON analysis_signals (analysis_id);
CREATE INDEX idx_analysis_signals_code ON analysis_signals (signal_code);
CREATE INDEX idx_analysis_signals_severity ON analysis_signals (severity);
CREATE INDEX idx_analysis_signals_evidence_gin ON analysis_signals USING GIN (evidence);

-- =========================================================
-- 7) Trigger para desnormalizar JSONB -> analysis_signals
--    Asi puedes seguir guardando signals como JSONB desde FastAPI
--    y ademas tenerlos en forma relacional.
-- =========================================================
CREATE OR REPLACE FUNCTION sync_analysis_signals()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    signal_item JSONB;
    v_weight INTEGER;
    v_severity TEXT;
BEGIN
    DELETE FROM analysis_signals WHERE analysis_id = NEW.id;

    IF NEW.signals IS NULL OR jsonb_typeof(NEW.signals) <> 'array' THEN
        RETURN NEW;
    END IF;

    FOR signal_item IN
        SELECT value
        FROM jsonb_array_elements(NEW.signals)
    LOOP
        v_weight :=
            CASE
                WHEN (signal_item->>'weight') ~ '^-?\d+$'
                    THEN (signal_item->>'weight')::INTEGER
                ELSE 0
            END;

        v_severity :=
            CASE UPPER(COALESCE(signal_item->>'severity', 'LOW'))
                WHEN 'LOW' THEN 'LOW'
                WHEN 'MEDIUM' THEN 'MEDIUM'
                WHEN 'HIGH' THEN 'HIGH'
                ELSE 'LOW'
            END;

        INSERT INTO analysis_signals (
            analysis_id,
            signal_code,
            severity,
            weight,
            explanation,
            evidence
        )
        VALUES (
            NEW.id,
            COALESCE(NULLIF(signal_item->>'id', ''), 'UNKNOWN_SIGNAL'),
            v_severity,
            v_weight,
            COALESCE(signal_item->>'explanation', ''),
            COALESCE(signal_item->'evidence', '{}'::jsonb)
        );
    END LOOP;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_sync_analysis_signals
AFTER INSERT OR UPDATE OF signals
ON analysis_results
FOR EACH ROW
EXECUTE FUNCTION sync_analysis_signals();

-- =========================================================
-- 8) system_settings
--    Para persistir /settings en el futuro
-- =========================================================
CREATE TABLE system_settings (
    key           TEXT PRIMARY KEY,
    value_json    JSONB NOT NULL,
    description   TEXT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO system_settings (key, value_json, description)
VALUES
    ('connection_mode', '"auto"'::jsonb, 'Modo global: auto | online | offline'),
    ('offline_fallback', 'true'::jsonb, 'Permitir fallback cuando no haya servicios externos')
ON CONFLICT (key) DO NOTHING;

COMMIT;
