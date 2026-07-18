package com.devsecops.vulncheckerbackend.services;

import com.devsecops.vulncheckerbackend.config.SshTunnelManager;
import com.devsecops.vulncheckerbackend.dto.WazuhCredentials;
import com.devsecops.vulncheckerbackend.entities.AgentEntity;
import com.devsecops.vulncheckerbackend.entities.VulnerabilityEntity;
import com.devsecops.vulncheckerbackend.entities.VulnerabilitySnapshotEntity;
import com.devsecops.vulncheckerbackend.repositories.AgentRepository;
import com.devsecops.vulncheckerbackend.repositories.VulnerabilityRepository;
import com.devsecops.vulncheckerbackend.repositories.VulnerabilitySnapshotRepository;
import com.jcraft.jsch.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.Executor;
import java.util.stream.Collectors;

/**
 * Servicio para sincronizar vulnerabilidades desde Wazuh (Elasticsearch) a través de túnel SSH.
 * La sincronización masiva actualiza el estado de las vulnerabilidades y registra eventos
 * en la tabla vulnerability_timelines.
 */
@Service
public class WazuhService {

    private static final Logger log = LoggerFactory.getLogger(WazuhService.class);
    private static final String VULN_INDEX = "wazuh-states-vulnerabilities*";

    private final SshTunnelManager tunnelManager;
    private final RestTemplate restTemplate;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final VulnerabilitySnapshotRepository snapshotRepository;
    private final AgentRepository agentRepository;
    //private final VulnerabilityTimelineService timelineService;
    private final Executor taskExecutor;

    public WazuhService(SshTunnelManager tunnelManager,
                        @Qualifier("wazuhRestTemplate") RestTemplate restTemplate,
                        VulnerabilityRepository vulnerabilityRepository,
                        VulnerabilitySnapshotRepository snapshotRepository,
                        AgentRepository agentRepository,
                        //VulnerabilityTimelineService timelineService,
                        @Qualifier("wazuhTaskExecutor") Executor taskExecutor) {
        this.tunnelManager = tunnelManager;
        this.restTemplate = restTemplate;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.snapshotRepository = snapshotRepository;
        this.agentRepository = agentRepository;
        //this.timelineService = timelineService;
        this.taskExecutor = taskExecutor;
    }

    // ======================= MÉTODOS PÚBLICOS DE CONSULTA A WAZUH (LEGACY) =======================
    // (Sin cambios en la lógica, solo ajuste interno para usar puerto dinámico)
    public Map<String, Object> getAllVulnerabilities(WazuhCredentials creds, int limit, int offset) throws Exception {
        int pageSize = Math.min(limit, 5000);
        String body = """
                {
                  "from": %d,
                  "size": %d,
                  "query": { "match_all": {} },
                  "sort": [{ "vulnerability.detected_at": "desc" }]
                }
                """.formatted(offset, pageSize);
        return executeWithTunnel(creds, body);
    }

    public Map<String, Object> getTopVulnerabilities(WazuhCredentials creds, int limit) throws Exception {
        return getAllVulnerabilities(creds, limit, 0);
    }

    public Map<String, Object> getVulnerabilitiesBySeverity(WazuhCredentials creds, String severity, int limit) throws Exception {
        String body = """
                {
                  "size": %d,
                  "query": {
                    "match": { "vulnerability.severity": "%s" }
                  }
                }
                """.formatted(limit, capitalize(severity));
        return executeWithTunnel(creds, body);
    }

    public Map<String, Object> getVulnerabilitiesByAgent(WazuhCredentials creds, String agentId, int limit) throws Exception {
        String body = """
                {
                  "size": %d,
                  "query": {
                    "bool": {
                      "should": [
                        { "term": { "agent.id": "%s" } },
                        { "term": { "wazuh.agent.id": "%s" } }
                      ],
                      "minimum_should_match": 1
                    }
                  }
                }
                """.formatted(limit, agentId, agentId);
        return executeWithTunnel(creds, body);
    }

    public Map<String, Object> getVulnerabilitiesByCve(WazuhCredentials creds, String cve) throws Exception {
        String body = """
                {
                  "size": 500,
                  "query": {
                    "match": { "vulnerability.id": "%s" }
                  }
                }
                """.formatted(cve.toUpperCase());
        return executeWithTunnel(creds, body);
    }

    public Map<String, Object> getCriticalVulnerabilities(WazuhCredentials creds) throws Exception {
        return getVulnerabilitiesBySeverity(creds, "Critical", 500);
    }

    public Map<String, Object> getVulnerabilitiesSummary(WazuhCredentials creds) throws Exception {
        String body = """
                {
                  "size": 0,
                  "aggs": {
                    "by_severity": {
                      "terms": { "field": "vulnerability.severity" }
                    }
                  }
                }
                """;
        return executeWithTunnel(creds, body);
    }

    // ======================= NUEVO: OBTENER CANTIDAD DE VULNERABILIDADES NUEVAS REMOTAS =======================
    public long getRemoteNewCount(WazuhCredentials creds, LocalDateTime since) throws Exception {
        Session session = null;
        try {
            session = tunnelManager.openTunnel(creds.sshHost(), 22, creds.sshUser(), creds.sshPassword());
            int localPort = tunnelManager.getLocalPort(session);
            String queryBody;
            if (since == null) {
                queryBody = "{ \"query\": { \"match_all\": {} } }";
            } else {
                String isoDate = since.atZone(ZoneId.systemDefault()).format(DateTimeFormatter.ISO_INSTANT);
                queryBody = String.format("""
                        {
                        "query": {
                            "range": {
                            "vulnerability.detected_at": {
                                "gt": "%s"
                            }
                            }
                        }
                        }
                        """, isoDate);
            }
            String url = buildWazuhUrl(localPort) + "/" + VULN_INDEX + "/_count";
            HttpHeaders headers = new HttpHeaders();
            String auth = creds.wazuhUser() + ":" + creds.wazuhPassword();
            String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
            headers.set("Authorization", "Basic " + encodedAuth);
            headers.setContentType(MediaType.APPLICATION_JSON);
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    url, HttpMethod.POST, new HttpEntity<>(queryBody, headers),
                    new ParameterizedTypeReference<Map<String, Object>>() {}
            );
            Map<String, Object> body = response.getBody();
            if (body == null || !body.containsKey("count")) {
                throw new RuntimeException("Respuesta inválida de Wazuh");
            }
            return Long.parseLong(body.get("count").toString());
        } finally {
            if (session != null) tunnelManager.closeTunnel(session);
        }
    }

    // ======================= SINCRONIZACIÓN MASIVA CON SSE (INCREMENTAL) =======================
    public void syncAllVulnerabilitiesMasive(WazuhCredentials creds, String taskId, SseEmitter emitter) {
        taskExecutor.execute(() -> {
            log.info("INICIANDO EXTRACCIÓN INCREMENTAL PARA: {}, taskId: {}", creds.sshHost(), taskId);
            try {
                performSync(creds, taskId, emitter);
                emitter.send(SseEmitter.event().name("complete").data(Map.of("status", "done")));
                emitter.complete();
            } catch (Exception e) {
                log.error("ERROR CRÍTICO EN HILO DE SINCRONIZACIÓN: ", e);
                try {
                    emitter.send(SseEmitter.event().name("error").data(Map.of("error", e.getMessage())));
                    emitter.completeWithError(e);
                } catch (IOException ex) {
                    log.error("No se pudo enviar error por SSE", ex);
                }
            }
        });
    }

    @SuppressWarnings("java:S2229")
    public void performSync(WazuhCredentials creds, String taskId, SseEmitter emitter) throws Exception {
        // 1. Obtener la fecha de la última sincronización exitosa
        LocalDateTime lastSync = vulnerabilityRepository.findMaxLastSync();
        boolean firstSync = (lastSync == null);
        log.info("Última sincronización: {}", lastSync);

        // 2. Vulnerabilidades activas actuales (para luego resolver las que ya no aparecen)
        List<VulnerabilityEntity> currentlyActive = vulnerabilityRepository.findByStatus("ACTIVE");
        Map<String, VulnerabilityEntity> activeByKey = currentlyActive.stream()
                .collect(Collectors.toMap(
                        v -> buildKey(v.getCve(), v.getAgentId(), v.getPackageName()),
                        v -> v,
                        (existing, replacement) -> existing
                ));
        Set<Long> seenIds = new HashSet<>();
        Map<Long, SnapshotCounter> countersByAgent = new HashMap<>();

        // 3. Paginación sobre Wazuh (solo elementos nuevos)
        int pageSize = 2000;
        Object[] lastSortValues = null;
        boolean hasMore = true;
        long processedTotal = 0;

        // Obtener el total de elementos nuevos para el progreso
        long remoteNewTotal = getRemoteNewCount(creds, lastSync);
        log.info("Se sincronizarán {} vulnerabilidades nuevas", remoteNewTotal);

        Session session = tunnelManager.openTunnel(creds.sshHost(), 22, creds.sshUser(), creds.sshPassword());
        int localPort = tunnelManager.getLocalPort(session);
        try {
            while (hasMore) {
                String searchAfterClause = (lastSortValues != null)
                        ? ", \"search_after\": [%s, \"%s\"]".formatted(lastSortValues[0], lastSortValues[1])
                        : "";

                String rangeFilter;
                if (firstSync) {
                    rangeFilter = "\"query\": { \"match_all\": {} }";
                } else {
                    String isoDate = lastSync.atZone(ZoneId.systemDefault()).format(DateTimeFormatter.ISO_INSTANT);
                    rangeFilter = String.format("""
                            "query": {
                                "range": {
                                    "vulnerability.detected_at": {
                                        "gt": "%s"
                                    }
                                }
                            }
                            """, isoDate);
                }

                String body = String.format("""
                        {
                          "size": %d,
                          "sort": [
                            { "vulnerability.detected_at": "desc" },
                            { "_id": "asc" }
                          ],
                          %s
                          %s
                        }
                        """, pageSize, rangeFilter, searchAfterClause);

                Map<String, Object> response = search(body, creds.wazuhUser(), creds.wazuhPassword(), localPort);

                if (response != null && response.containsKey("hits")) {
                    Map<String, Object> hitsStructure = (Map<String, Object>) response.get("hits");
                    List<Map<String, Object>> hits = (List<Map<String, Object>>) hitsStructure.get("hits");

                    if (hits == null || hits.isEmpty()) {
                        hasMore = false;
                    } else {
                        int batchSize = hits.size();
                        processHitsBatch(hits, activeByKey, seenIds, countersByAgent);
                        processedTotal += batchSize;

                        // Enviar progreso vía SSE
                        emitter.send(SseEmitter.event().name("progress").data(Map.of(
                                "processed", processedTotal,
                                "total", remoteNewTotal,
                                "percent", (int)((double)processedTotal / remoteNewTotal * 100),
                                "taskId", taskId
                        )));
                        log.debug("Progreso: {}/{}", processedTotal, remoteNewTotal);

                        lastSortValues = ((List<Object>) hits.get(hits.size() - 1).get("sort")).toArray();
                    }
                } else {
                    hasMore = false;
                }
            }
        } finally {
            tunnelManager.closeTunnel(session);  // Cerrar siempre el túnel después de la sincronización
        }

        // 4. Guardar snapshots de conteo por agente
        countersByAgent.values().forEach(this::saveSnapshot);

        // 5. Resolver vulnerabilidades que ya no aparecieron en esta sincronización
        List<Long> resolvedIds = new ArrayList<>();
        for (VulnerabilityEntity vuln : currentlyActive) {
            if (!seenIds.contains(vuln.getId())) {
                resolvedIds.add(vuln.getId());
                //timelineService.registerEvent(vuln, vuln.getStatus(), "RESOLVED", "RESOLVED");
            }
        }
        if (!resolvedIds.isEmpty()) {
            int updated = vulnerabilityRepository.updateStatusByIds(resolvedIds, "RESOLVED");
            log.info("Se resolvieron {} vulnerabilidades", updated);
        }
    }

    // ======================= PROCESAMIENTO DE BATCHES (ÍNTEGRO, SIN CAMBIOS) =======================
    @SuppressWarnings("unchecked")
    private void processHitsBatch(List<Map<String, Object>> hits,
                                  Map<String, VulnerabilityEntity> activeByKey,
                                  Set<Long> seenIds,
                                  Map<Long, SnapshotCounter> countersByAgent) {
        List<VulnerabilityEntity> toSave = new ArrayList<>();
        List<VulnerabilityEntity> toUpdate = new ArrayList<>();
        Set<String> processedKeys = new HashSet<>(); // Evita duplicados dentro del mismo lote

        for (Map<String, Object> hit : hits) {
            try {
                Map<String, Object> source = (Map<String, Object>) hit.get("_source");
                Map<String, Object> v = (Map<String, Object>) source.get("vulnerability");
                Map<String, Object> p = (Map<String, Object>) source.get("package");

                // SOPORTE HÍBRIDO: Buscar 'agent' en la raíz (Wazuh nuevo) o dentro de 'wazuh' (Wazuh viejo)
                Map<String, Object> agentMap = (Map<String, Object>) source.get("agent");
                if (agentMap == null) {
                    Map<String, Object> wazuh = (Map<String, Object>) source.get("wazuh");
                    if (wazuh != null) {
                        agentMap = (Map<String, Object>) wazuh.get("agent");
                    }
                }

                if (v == null || agentMap == null) {
                    log.warn("Hit sin vulnerability o wazuh.agent, omitido");
                    continue;
                }

                // --- Datos básicos ---
                String cve = (String) v.get("id");
                String wazuhAgentId = (String) agentMap.get("id");
                String agentName = (String) agentMap.get("name");
                String agentVersion = (String) agentMap.get("version");
                String pkgName = (p != null) ? (String) p.get("name") : null;
                String pkgVersion = (p != null) ? (String) p.get("version") : null;
                String pkgType = (p != null) ? (String) p.get("type") : null;
                String pkgDescription = (p != null) ? (String) p.get("description") : null;
                String severity = (String) v.get("severity");
                Boolean underEvaluation = (Boolean) v.get("under_evaluation");
                String ctiReference = null;
                Map<String, Object> scanner = (Map<String, Object>) v.get("scanner");
                if (scanner != null) {
                    ctiReference = (String) scanner.get("reference");
                }

                // --- Datos del SO del agente ---
                Map<String, Object> host = (Map<String, Object>) agentMap.get("host");
                String osType = null, osFullName = null, osPlatform = null;
                if (host != null) {
                    Map<String, Object> os = (Map<String, Object>) host.get("os");
                    if (os != null) {
                        osType = (String) os.get("type");
                        osPlatform = (String) os.get("platform");
                        String name = (String) os.get("name");
                        String version = (String) os.get("version");
                        String full = (String) os.get("full");
                        if (full != null && !full.isBlank()) {
                            osFullName = full;
                        } else if (name != null && version != null) {
                            osFullName = name + " " + version;
                        } else {
                            osFullName = name;
                        }
                    }
                }

                // --- Crear o actualizar agente ---
                AgentEntity agent = agentRepository.findByWazuhAgentId(wazuhAgentId).orElseGet(AgentEntity::new);
                agent.setWazuhAgentId(wazuhAgentId);
                agent.setName(agentName);
                agent.setVersion(agentVersion);
                agent.setOsType(osType);
                agent.setOsFullName(osFullName);
                agent.setOsPlataform(osPlatform);
                agent.setLastSeen(LocalDateTime.now(ZoneOffset.UTC));
                agent = agentRepository.save(agent);
                Long agentIdNum = agent.getId();

                // --- Contar para snapshots ---
                SnapshotCounter counter = countersByAgent.computeIfAbsent(agentIdNum, k -> new SnapshotCounter());
                counter.count(agentIdNum, severity);

                // --- Clave única y control de duplicados en este lote ---
                String key = buildKey(cve, agentIdNum, pkgName);
                if (processedKeys.contains(key)) {
                    log.debug("Hit duplicado en el mismo lote, omitiendo: {}", key);
                    continue;
                }
                processedKeys.add(key);

                // --- Buscar si ya existe en el mapa de activas (vienen de BD) ---
                VulnerabilityEntity existing = activeByKey.get(key);
                Double cvssScore = extractCvssScore(v);
                LocalDateTime detectedAt = parseDateTime(v.get("detected_at"));

                if (existing != null) {
                    // Vulnerabilidad ya activa → actualizar
                    updateExistingVulnerability(existing, severity, cvssScore, underEvaluation, ctiReference,
                            pkgVersion, pkgType, pkgDescription);
                    toUpdate.add(existing);
                    seenIds.add(existing.getId());
                } else {
                    // Nueva vulnerabilidad → crear
                    VulnerabilityEntity entity = new VulnerabilityEntity();
                    entity.setCve(cve);
                    entity.setAgentId(agentIdNum);
                    entity.setPackageName(pkgName);
                    entity.setPackageVersion(pkgVersion);
                    entity.setPackageType(pkgType);
                    entity.setSeverity(severity);
                    entity.setStatus("ACTIVE");
                    entity.setUnderEvaluation(underEvaluation != null ? underEvaluation : false);
                    entity.setCtiReference(ctiReference);
                    entity.setDescription(pkgDescription);
                    entity.setCvss3Score(cvssScore);
                    entity.setDetectionTime(detectedAt);
                    entity.setLastDetection(detectedAt);
                    entity.setLastSync(LocalDateTime.now(ZoneOffset.UTC));
                    toSave.add(entity);
                }
            } catch (Exception e) {
                log.warn("Error procesando hit: {}", e.getMessage(), e);
            }
        }

        // --- Guardar nuevas vulnerabilidades y registrar eventos DETECTED ---
        if (!toSave.isEmpty()) {
            List<VulnerabilityEntity> saved = vulnerabilityRepository.saveAll(toSave);
            for (VulnerabilityEntity v : saved) {
                //timelineService.registerEvent(v, null, "ACTIVE", "DETECTED");
                seenIds.add(v.getId());
                activeByKey.put(buildKey(v.getCve(), v.getAgentId(), v.getPackageName()), v);
            }
        }
        // --- Actualizar las existentes ---
        if (!toUpdate.isEmpty()) {
            vulnerabilityRepository.saveAll(toUpdate);
        }
    }

    // ======================= MÉTODOS AUXILIARES =======================
    private void updateExistingVulnerability(VulnerabilityEntity existing, String severity, Double cvssScore,
                                             Boolean underEvaluation, String ctiReference, String pkgVersion,
                                             String pkgType, String pkgDescription) {
        existing.setSeverity(severity);
        existing.setCvss3Score(cvssScore);
        existing.setUnderEvaluation(underEvaluation != null ? underEvaluation : false);
        existing.setCtiReference(ctiReference);
        existing.setPackageVersion(pkgVersion);
        existing.setPackageType(pkgType);
        existing.setDescription(pkgDescription);
        existing.setLastDetection(LocalDateTime.now(ZoneOffset.UTC));
        existing.setLastSync(LocalDateTime.now(ZoneOffset.UTC));
    }

    private String buildKey(String cve, Long agentId, String packageName) {
        return cve + "|" + agentId + "|" + (packageName != null ? packageName : "");
    }

    private Double extractCvssScore(Map<String, Object> vulnerabilityMap) {
        Map<String, Object> scoreObj = (Map<String, Object>) vulnerabilityMap.get("score");
        if (scoreObj != null && scoreObj.get("base") != null) {
            try {
                return Double.valueOf(scoreObj.get("base").toString());
            } catch (NumberFormatException e) {
                return 0.0;
            }
        }
        return 0.0;
    }

    private LocalDateTime parseDateTime(Object dateObj) {
        if (dateObj == null) return null;
        try {
            if (dateObj instanceof String) {
                return ZonedDateTime.parse((String) dateObj).toLocalDateTime();
            } else if (dateObj instanceof Number) {
                long millis = ((Number) dateObj).longValue();
                if (millis > 1_000_000_000_000L) {
                    return Instant.ofEpochMilli(millis).atZone(ZoneId.systemDefault()).toLocalDateTime();
                } else {
                    return Instant.ofEpochSecond(millis).atZone(ZoneId.systemDefault()).toLocalDateTime();
                }
            }
        } catch (Exception e) {
            log.warn("Error parseando fecha: {}", dateObj);
        }
        return null;
    }

    private void saveSnapshot(SnapshotCounter counter) {
        if (counter.agentId == null) return;
        VulnerabilitySnapshotEntity snap = new VulnerabilitySnapshotEntity();
        snap.setAgentId(counter.agentId);
        snap.setCriticalCount(counter.crit);
        snap.setHighCount(counter.high);
        snap.setMediumCount(counter.med);
        snap.setLowCount(counter.low);
        snap.setTotalCount(counter.getTotal());
        snapshotRepository.save(snap);
        log.info("Snapshot guardado para agente {}: total {}", counter.agentId, snap.getTotalCount());
    }

    private static class SnapshotCounter {
        Long agentId;
        int crit, high, med, low;

        void count(Long agentId, String severity) {
            this.agentId = agentId;
            if (severity == null) return;
            switch (severity.toLowerCase()) {
                case "critical": crit++; break;
                case "high": high++; break;
                case "medium": med++; break;
                case "low": low++; break;
                default: break;
            }
        }

        int getTotal() {
            return crit + high + med + low;
        }
    }

    // ======================= INFRAESTRUCTURA (túnel y comunicación con Elasticsearch) =======================
    private Map<String, Object> executeWithTunnel(WazuhCredentials creds, String queryBody) throws Exception {
        Session session = null;
        try {
            session = tunnelManager.openTunnel(creds.sshHost(), 22, creds.sshUser(), creds.sshPassword());
            int localPort = tunnelManager.getLocalPort(session);
            return search(queryBody, creds.wazuhUser(), creds.wazuhPassword(), localPort);
        } finally {
            if (session != null) {
                tunnelManager.closeTunnel(session);
            }
        }
    }

    private Map<String, Object> search(String queryBody, String user, String password, int localPort) {
        String auth = user + ":" + password;
        String credentials = Base64.getEncoder().encodeToString(auth.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic " + credentials);
        headers.setContentType(MediaType.APPLICATION_JSON);
        String url = buildWazuhUrl(localPort) + "/" + VULN_INDEX + "/_search";
        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                url, HttpMethod.POST, new HttpEntity<>(queryBody, headers),
                new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {}
        );
        return response.getBody();
    }

    private String buildWazuhUrl(int localPort) {
        return "https://127.0.0.1:" + localPort;
    }

    private String capitalize(String s) {
        if (s == null || s.isEmpty()) return s;
        return Character.toUpperCase(s.charAt(0)) + s.substring(1).toLowerCase();
    }
}