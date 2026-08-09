-- =============================================================================
-- Migration: V4__timeline_unico_por_cve.sql
-- Objetivos:
--   1. Hacer única la línea de tiempo por CVE: la PK pasa a ser
--      (time, infrastructure_credentials_id, w_cve), sin w_package_name.
--   2. Eliminar las columnas de paquete (w_package_name, w_package_type,
--      w_package_version) por ser redundantes con active_vulnerabilities.
-- =============================================================================

-- 1. Limpiar posibles duplicados históricos dejando una sola fila por
--    (time, infrastructure_credentials_id, w_cve) antes de crear la PK.
DELETE FROM vulnerability_timeline a
USING vulnerability_timeline b
WHERE a.time = b.time
  AND a.infrastructure_credentials_id = b.infrastructure_credentials_id
  AND a.w_cve = b.w_cve
  AND a.ctid < b.ctid;

-- 2. Eliminar la PK vieja (incluía w_package_name)
ALTER TABLE vulnerability_timeline DROP CONSTRAINT pk_vulnerability_timeline;

-- 3. Eliminar columnas de paquete (redundantes con active_vulnerabilities)
ALTER TABLE vulnerability_timeline DROP COLUMN IF EXISTS w_package_name;
ALTER TABLE vulnerability_timeline DROP COLUMN IF EXISTS w_package_type;
ALTER TABLE vulnerability_timeline DROP COLUMN IF EXISTS w_package_version;

-- 4. Nueva PK: única por CVE (time, infrastructure_credentials_id, w_cve)
ALTER TABLE vulnerability_timeline
    ADD CONSTRAINT pk_vulnerability_timeline PRIMARY KEY (time, infrastructure_credentials_id, w_cve);
