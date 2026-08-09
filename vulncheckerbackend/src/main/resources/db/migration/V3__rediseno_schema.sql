-- =============================================================================
-- Migration: V3__rediseno_schema.sql
-- Objetivos:
--   1. Renombrar vulnerabilities -> active_vulnerabilities (solo guarda activas).
--   2. Prefijo w_ a las columnas cuyo origen es Wazuh (solo nombres de columna).
--   3. Eliminar columnas redundantes: status y last_detection.
--   4. Recrear vulnerability_timeline por CVE (sin agent_id en la PK), con w_ en
--      las columnas de Wazuh y infrastructure_credentials_id en la clave.
--   5. Recrear las vistas materializadas y el procedimiento de refresco.
-- =============================================================================

-- 1. Eliminar vistas materializadas que referencian a la tabla vieja
DROP MATERIALIZED VIEW IF EXISTS mv_critical_vulns;
DROP MATERIALIZED VIEW IF EXISTS mv_recent_vulns;
DROP MATERIALIZED VIEW IF EXISTS mv_vulnerable_packages;
DROP MATERIALIZED VIEW IF EXISTS mv_monthly_resolution_trend;
DROP MATERIALIZED VIEW IF EXISTS mv_daily_severity_flow;
DROP MATERIALIZED VIEW IF EXISTS mv_weekly_cvss_impact;

-- 2. Renombrar la tabla
ALTER TABLE vulnerabilities RENAME TO active_vulnerabilities;

-- 3. Eliminar columnas redundantes
ALTER TABLE active_vulnerabilities DROP COLUMN IF EXISTS status;
ALTER TABLE active_vulnerabilities DROP COLUMN IF EXISTS last_detection;

-- 4. Prefijo w_ en las columnas de origen Wazuh
ALTER TABLE active_vulnerabilities RENAME COLUMN cve TO w_cve;
ALTER TABLE active_vulnerabilities RENAME COLUMN description TO w_description;
ALTER TABLE active_vulnerabilities RENAME COLUMN severity TO w_severity;
ALTER TABLE active_vulnerabilities RENAME COLUMN cvss3_score TO w_cvss3_score;
ALTER TABLE active_vulnerabilities RENAME COLUMN under_evaluation TO w_under_evaluation;
ALTER TABLE active_vulnerabilities RENAME COLUMN cti_reference TO w_cti_reference;
ALTER TABLE active_vulnerabilities RENAME COLUMN package_name TO w_package_name;
ALTER TABLE active_vulnerabilities RENAME COLUMN package_type TO w_package_type;
ALTER TABLE active_vulnerabilities RENAME COLUMN package_version TO w_package_version;
ALTER TABLE active_vulnerabilities RENAME COLUMN detection_time TO w_detection_time;

-- 5. Renombrar la restricción única para reflejar el nuevo nombre
ALTER TABLE active_vulnerabilities DROP CONSTRAINT IF EXISTS uq_vulnerabilities_cve_agent_package;
ALTER TABLE active_vulnerabilities
    ADD CONSTRAINT uq_active_vulns_cve_agent_package UNIQUE (w_cve, agent_id, w_package_name);

-- 6. Recrear vulnerability_timeline como tabla por CVE (sin agent_id en la PK)
DROP TABLE IF EXISTS vulnerability_timeline;

CREATE TABLE vulnerability_timeline (
    time TIMESTAMPTZ NOT NULL,
    infrastructure_credentials_id BIGINT NOT NULL,
    w_cve VARCHAR(255) NOT NULL,
    w_package_name VARCHAR(255) NOT NULL,
    w_package_type VARCHAR(255),
    w_package_version VARCHAR(255),
    status VARCHAR(255) NOT NULL,       -- 'ACTIVE', 'RESOLVED' (lo calcula el sistema, sin prefijo)
    w_cvss3_score NUMERIC(3, 1),
    w_severity VARCHAR(255) NOT NULL,   -- 'Critical', 'High', 'Medium', 'Low'

    CONSTRAINT pk_vulnerability_timeline PRIMARY KEY (time, infrastructure_credentials_id, w_cve, w_package_name)
);

SELECT create_hypertable('vulnerability_timeline', 'time', chunk_time_interval => INTERVAL '7 days');

CREATE INDEX idx_timeline_filters ON vulnerability_timeline (infrastructure_credentials_id, w_cve, w_severity, status, time DESC);

-- 7. Recrear vistas materializadas sobre el nuevo esquema

-- Vulnerabilidades Críticas
CREATE MATERIALIZED VIEW mv_critical_vulns AS
SELECT
    id,
    agent_id,
    w_cve,
    w_severity,
    w_cvss3_score,
    w_package_name,
    w_detection_time
FROM active_vulnerabilities
WHERE w_severity = 'Critical';

-- Vulnerabilidades recientes (Año 2024 en adelante)
CREATE MATERIALIZED VIEW mv_recent_vulns AS
SELECT
    id,
    agent_id,
    w_cve,
    w_severity,
    w_cvss3_score,
    w_package_name,
    w_detection_time
FROM active_vulnerabilities
WHERE EXTRACT(YEAR FROM w_detection_time) >= 2024;

-- Piezas de software más vulnerables (Top 50); ya no filtra por status porque la tabla solo tiene activas
CREATE MATERIALIZED VIEW mv_vulnerable_packages AS
SELECT
    w_package_name,
    w_package_type,
    COUNT(DISTINCT agent_id) as affected_agents,
    COUNT(id) as total_cves,
    MAX(w_cvss3_score) as highest_score
FROM active_vulnerabilities
GROUP BY w_package_name, w_package_type
ORDER BY total_cves DESC
LIMIT 50;

-- Tendencia de resolución de vulnerabilidades por mes
CREATE MATERIALIZED VIEW mv_monthly_resolution_trend AS
SELECT
    DATE_TRUNC('month', time) as period_month,
    status,
    COUNT(*) as event_count
FROM vulnerability_timeline
GROUP BY DATE_TRUNC('month', time), status
ORDER BY period_month DESC;

-- Evolución diaria por severidad y estado
CREATE MATERIALIZED VIEW mv_daily_severity_flow AS
SELECT
    DATE_TRUNC('day', time) AS event_date,
    w_severity AS severity,
    status,
    COUNT(*) AS event_count
FROM vulnerability_timeline
GROUP BY DATE_TRUNC('day', time), w_severity, status
ORDER BY event_date DESC;

-- Impacto semanal por severidad y CVSS
CREATE MATERIALIZED VIEW mv_weekly_cvss_impact AS
SELECT
    DATE_TRUNC('week', time) AS week_start,
    w_severity AS severity,
    ROUND(AVG(w_cvss3_score), 2) AS avg_cvss,
    MAX(w_cvss3_score) AS max_cvss,
    COUNT(*) AS total_events
FROM vulnerability_timeline
GROUP BY DATE_TRUNC('week', time), w_severity
ORDER BY week_start DESC;

-- 8. Procedimiento almacenado de refresco (mismo cuerpo)
CREATE OR REPLACE PROCEDURE refresh_vuln_views()
LANGUAGE plpgsql
AS $$
BEGIN
    REFRESH MATERIALIZED VIEW mv_critical_vulns;
    REFRESH MATERIALIZED VIEW mv_recent_vulns;
    REFRESH MATERIALIZED VIEW mv_vulnerable_packages;

    REFRESH MATERIALIZED VIEW mv_monthly_resolution_trend;
    REFRESH MATERIALIZED VIEW mv_daily_severity_flow;
    REFRESH MATERIALIZED VIEW mv_weekly_cvss_impact;
END;
$$;
