-- 1. Crear Vistas Materializadas para los filtros comunes

-- Ejemplo A: Vulnerabilidades Críticas (Filtro común de criticidad)
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

-- Ejemplo B: Vulnerabilidades recientes (Año 2024 en adelante)
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

-- 2. Crear el Procedimiento Almacenado
CREATE OR REPLACE PROCEDURE refresh_vuln_views()
LANGUAGE plpgsql
AS $$
BEGIN
    REFRESH MATERIALIZED VIEW mv_critical_vulns;
    REFRESH MATERIALIZED VIEW mv_recent_vulns;
END;
$$;