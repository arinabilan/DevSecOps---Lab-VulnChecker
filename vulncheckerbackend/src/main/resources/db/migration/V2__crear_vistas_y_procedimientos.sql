-- 1. Crear Vistas Materializadas para los filtros comunes

-- Vulnerabilidades Críticas (Filtro común de criticidad)
CREATE MATERIALIZED VIEW mv_critical_vulns AS
SELECT 
    id, 
    agent_id, 
    cve, 
    severity, 
    cvss3_score, 
    package_name, 
    detection_time 
FROM vulnerabilities 
WHERE severity = 'Critical';

-- Vulnerabilidades recientes (Año 2024 en adelante)
CREATE MATERIALIZED VIEW mv_recent_vulns AS
SELECT 
    id, 
    agent_id, 
    cve, 
    severity, 
    cvss3_score, 
    package_name, 
    detection_time 
FROM vulnerabilities 
WHERE EXTRACT(YEAR FROM detection_time) >= 2024;

-- Origen de los problemas según sistema operativo y plataforma
CREATE MATERIALIZED VIEW mv_risk_by_os AS
SELECT 
    a.os_type,
    a.os_plataform,
    COUNT(v.id) as total_vulnerabilities,
    SUM(CASE WHEN lower(v.severity) = 'critical' THEN 1 ELSE 0 END) as critical_count
FROM agents a
JOIN vulnerabilities v ON a.id = v.agent_id
WHERE v.status = 'ACTIVE'
GROUP BY a.os_type, a.os_plataform;

-- Piezas de software más vulnerables (Top 50)
CREATE MATERIALIZED VIEW mv_vulnerable_packages AS
SELECT 
    package_name,
    package_type,
    COUNT(DISTINCT agent_id) as affected_agents,
    COUNT(id) as total_cves,
    MAX(cvss3_score) as highest_score
FROM vulnerabilities
WHERE status = 'ACTIVE'
GROUP BY package_name, package_type
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

-- Esta vista agrupa los eventos día por día, separados por severidad y estado
-- para construir líneas que muestre la evolución de la criticidad y el estado de las vulnerabilidades a lo largo del tiempo.
CREATE MATERIALIZED VIEW mv_daily_severity_flow AS
SELECT 
    DATE_TRUNC('day', time) AS event_date,
    severity,
    status,
    COUNT(*) AS event_count
FROM vulnerability_timeline
GROUP BY DATE_TRUNC('day', time), severity, status
ORDER BY event_date DESC;

-- Esta vista proporciona un resumen semanal del impacto de las 
-- vulnerabilidades según su severidad y el puntaje CVSS promedio y máximo.
CREATE MATERIALIZED VIEW mv_weekly_cvss_impact AS
SELECT 
    DATE_TRUNC('week', time) AS week_start,
    severity,
    ROUND(AVG(cvss3_score), 2) AS avg_cvss,
    MAX(cvss3_score) AS max_cvss,
    COUNT(*) AS total_events
FROM vulnerability_timeline
GROUP BY DATE_TRUNC('week', time), severity
ORDER BY week_start DESC;




-- 2. Crear el Procedimiento Almacenado
CREATE OR REPLACE PROCEDURE refresh_vuln_views()
LANGUAGE plpgsql
AS $$
BEGIN
    -- vulnerabilities
    REFRESH MATERIALIZED VIEW mv_critical_vulns;
    REFRESH MATERIALIZED VIEW mv_recent_vulns;
    REFRESH MATERIALIZED VIEW mv_risk_by_os;
    REFRESH MATERIALIZED VIEW mv_vulnerable_packages;
    

    -- vulnerability_timeline
    REFRESH MATERIALIZED VIEW mv_monthly_resolution_trend;
    REFRESH MATERIALIZED VIEW mv_daily_severity_flow;
    REFRESH MATERIALIZED VIEW mv_weekly_cvss_impact;
END;
$$;