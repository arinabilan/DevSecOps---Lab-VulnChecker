-- =============================================================================
-- Migration: V6__agregar_vista_os.sql
-- Objetivos:
--   1. Crear vista materializada para recuperar el OS del agente asociado a la vulnerabilidad.
--   2. Actualizar el procedimiento almacenado para incluir el refresco de esta nueva vista.
-- =============================================================================

-- 1. Crear la vista materializada (haciendo match puro entre agentes y vulnerabilidades activas)
CREATE MATERIALIZED VIEW mv_agent_os_vulnerabilities AS
SELECT 
    -- Datos del Agente (Sistema Operativo)
    a.id AS agent_id,
    a.name AS agent_name,
    a.os_type,
    a.os_full_name,
    a.os_plataform,
    
    -- Datos de la Vulnerabilidad Activa
    av.w_cve,
    av.w_severity,
    av.w_cvss3_score,
    av.w_package_name
FROM active_vulnerabilities av
JOIN agents a ON av.agent_id = a.id;

-- 2. Sobreescribir el procedimiento almacenado para agregar la nueva vista al final
CREATE OR REPLACE PROCEDURE refresh_vuln_views()
LANGUAGE plpgsql
AS $$
BEGIN
    -- Vistas basadas en active_vulnerabilities (creadas en V3)
    REFRESH MATERIALIZED VIEW mv_critical_vulns;
    REFRESH MATERIALIZED VIEW mv_recent_vulns;
    REFRESH MATERIALIZED VIEW mv_vulnerable_packages;

    -- Vistas basadas en el timeline y estado actual (modificadas en V5)
    REFRESH MATERIALIZED VIEW mv_daily_severity_flow;
    REFRESH MATERIALIZED VIEW mv_weekly_cvss_impact;
    
    -- (Nota: mv_monthly_resolution_trend se asume que sigue existiendo desde V3)
    REFRESH MATERIALIZED VIEW mv_monthly_resolution_trend;

    -- NUEVA VISTA: Refresco del match de Sistema Operativo
    REFRESH MATERIALIZED VIEW mv_agent_os_vulnerabilities;
END;
$$;