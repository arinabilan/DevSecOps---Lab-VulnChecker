-- =============================================================================
-- Migration: V5__timeline_sin_severidad_ni_cvss.sql
-- Objetivos:
--   1. Eliminar w_severity y w_cvss3_score de vulnerability_timeline por ser
--      redundantes con active_vulnerabilities.
--   2. Redefinir mv_daily_severity_flow y mv_weekly_cvss_impact para que lean
--      severidad/CVSS desde active_vulnerabilities (estado actual), ya que el
--      timeline queda solo como registro de eventos (time, cve, status).
-- =============================================================================

-- 1. Eliminar las vistas materializadas que dependen de las columnas
DROP MATERIALIZED VIEW IF EXISTS mv_daily_severity_flow;
DROP MATERIALIZED VIEW IF EXISTS mv_weekly_cvss_impact;

-- 2. Eliminar el índice que incluía w_severity (depende de la columna)
DROP INDEX IF EXISTS idx_timeline_filters;

-- 3. Eliminar columnas redundantes del timeline
ALTER TABLE vulnerability_timeline DROP COLUMN w_severity;
ALTER TABLE vulnerability_timeline DROP COLUMN w_cvss3_score;

-- 4. Recrear el índice de filtros sin severidad
CREATE INDEX idx_timeline_filters ON vulnerability_timeline (infrastructure_credentials_id, w_cve, status, time DESC);

-- 5. Redefinir las vistas desde active_vulnerabilities (estado actual)

-- Evolución diaria por severidad (de las vulnerabilidades activas actuales)
CREATE MATERIALIZED VIEW mv_daily_severity_flow AS
SELECT
    DATE_TRUNC('day', w_detection_time) AS event_date,
    w_severity AS severity,
    COUNT(*) AS event_count
FROM active_vulnerabilities
WHERE w_detection_time IS NOT NULL
GROUP BY DATE_TRUNC('day', w_detection_time), w_severity
ORDER BY event_date DESC;

-- Impacto semanal por severidad y CVSS (de las vulnerabilidades activas actuales)
CREATE MATERIALIZED VIEW mv_weekly_cvss_impact AS
SELECT
    DATE_TRUNC('week', w_detection_time) AS week_start,
    w_severity AS severity,
    ROUND(AVG(w_cvss3_score)::numeric, 2) AS avg_cvss,
    MAX(w_cvss3_score) AS max_cvss,
    COUNT(*) AS total_events
FROM active_vulnerabilities
WHERE w_detection_time IS NOT NULL
GROUP BY DATE_TRUNC('week', w_detection_time), w_severity
ORDER BY week_start DESC;
