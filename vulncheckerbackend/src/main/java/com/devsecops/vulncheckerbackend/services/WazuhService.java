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
    private final InfrastructureCredentialService infrastructureCredentialService;
    private final VulnerabilityTimelineService timelineService;
    private final Executor taskExecutor;

    public WazuhService(SshTunnelManager tunnelManager,
                        @Qualifier("wazuhRestTemplate") RestTemplate restTemplate,
                        VulnerabilityRepository vulnerabilityRepository,
                        VulnerabilitySnapshotRepository snapshotRepository,
                        AgentRepository agentRepository,
                        InfrastructureCredentialService infrastructureCredentialService,
                        VulnerabilityTimelineService timelineService,
                        @Qualifier("wazuhTaskExecutor") Executor taskExecutor) {
        this.tunnelManager = tunnelManager;
        this.restTemplate = restTemplate;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.snapshotRepository = snapshotRepository;
        this.agentRepository = agentRepository;
        this.infrastructureCredentialService = infrastructureCredentialService;
        this.timelineService = timelineService;
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
                performSync(creds, taskId, emitter, true); // forceFullSync = true para sincronización completa
                try {
                    emitter.send(SseEmitter.event().name("complete").data(Map.of("status", "done")));
                    emitter.complete();
                } catch (IOException e) {
                    log.error("No se pudo enviar evento de finalización por SSE", e);
                }
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

    /**
     * Realiza la sincronización incremental de vulnerabilidades desde Wazuh.
     * <p>
     * 1. Obtiene la fecha de la última sincronización exitosa.
     * 2. Recupera las vulnerabilidades activas actuales de la base de datos.
     * 3. Realiza paginación sobre Wazuh para obtener vulnerabilidades nuevas o actualizadas.
     * 4. Guarda snapshots de conteo por agente.
     * 5. Resuelve vulnerabilidades que ya no aparecen en la sincronización.
     * <p>
     * Se envía progreso vía SSE al cliente.
     * <p>
     * @param creds Credenciales de Wazuh y SSH.
     * @param taskId Identificador único de la tarea para que el cliente frontend pueda rastrear el progreso.
     * @param emitter Canal de comunicación asincrono SseEmitter para enviar eventos de progreso al cliente.
     * @param forceFullSync Indica si se debe forzar una sincronización completa.
     */
    @SuppressWarnings("java:S2229")
    public void performSync(WazuhCredentials creds, String taskId, SseEmitter emitter, boolean forceFullSync) throws Exception {
        // 1. Decisión de estrategia: Será FULL si se solicita explícitamente O si es la primera vez que se ejecuta
        LocalDateTime lastSync = vulnerabilityRepository.findMaxLastSync();
        boolean executeFullQuery = forceFullSync || (lastSync == null);
        log.info("Última sincronización en BD: {}. Estrategia elegida: {}", 
                lastSync, executeFullQuery ? "FULL SYNC (Barrido Completo)" : "INCREMENTAL (Solo Nuevas)");

        // 2. Vulnerabilidades activas pertenecientes al wazuh con el que se está sincronizando
        Long infraCredId = infrastructureCredentialService.getIdByWazuhCredentials(creds);
        List<VulnerabilityEntity> currentlyActive = vulnerabilityRepository.findByInfrastructureCredentialsId(infraCredId);
        // Map<Key: cve|agentId|packageName, Value: VulnerabilityEntity>
        // una vulnerabilidad se considera única por la combinación de CVE, agente y paquete
        Map<String, VulnerabilityEntity> activeByKey = currentlyActive.stream()
                .collect(Collectors.toMap(
                        v -> buildKey(v.getCve(), v.getAgentId(), v.getPackageName()),
                        v -> v,
                        (existing, replacement) -> existing
                ));
        // Conjuntos a nivel CVE (agregado entre agentes y paquetes) para detectar transiciones de estado
        Set<String> previousActiveCves = currentlyActive.stream()
                .map(v -> buildCveKey(v.getCve()))
                .collect(Collectors.toSet());
        // Set de IDs de vulnerabilidades vistas durante esta sincronización
        // las vulnerabilidades que esten en currentlyActive pero no en seenIds se considerarán RESOLVED
        Set<Long> seenIds = new HashSet<>();
        // CVEs vistos durante esta sincronización (sin duplicar por agente)
        Set<String> seenCves = new HashSet<>();
        // Map<Key: agentId, Value: SnapshotCounter> para contar vulnerabilidades por agente y severidad
        Map<Long, SnapshotCounter> countersByAgent = new HashMap<>();

        // 3. Paginación sobre Wazuh (solo elementos nuevos)
        int pageSize = 5000;
        Object[] lastSortValues = null; // cursor de paginación para Elasticsearch
        boolean hasMore = true;
        long processedTotal = 0;

        // Obtener el total de elementos para el progreso
        long remoteNewTotal = getRemoteNewCount(creds, executeFullQuery ? null : lastSync);
        log.info("Se procesarán {} vulnerabilidades", remoteNewTotal);

        Session session = tunnelManager.openTunnel(creds.sshHost(), 22, creds.sshUser(), creds.sshPassword());
        int localPort = tunnelManager.getLocalPort(session);
        try {
            while (hasMore) {
                String searchAfterClause = (lastSortValues != null)
                        ? ", \"search_after\": [%s, \"%s\"]".formatted(lastSortValues[0], lastSortValues[1])
                        : "";

                String rangeFilter;
                if (executeFullQuery) { // Obtener todas las vulnerabilidades
                    rangeFilter = "\"query\": { \"match_all\": {} }";
                } else { // si no es la primera sincronización, obtener las vulnerabilidades "gt" (greater than) lastSync
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

                // Ejecutar la búsqueda en Wazuh de las ultimas 2000 vulnerabilidades a través del túnel SSH
                Map<String, Object> response = search(body, creds.wazuhUser(), creds.wazuhPassword(), localPort);

                if (response != null && response.containsKey("hits")) {
                    Map<String, Object> hitsStructure = (Map<String, Object>) response.get("hits");
                    List<Map<String, Object>> hits = (List<Map<String, Object>>) hitsStructure.get("hits");
                
                    // Condición de salida: si no hay más hits, terminar el bucle
                    if (hits == null || hits.isEmpty()) {
                        hasMore = false;
                    } else {
                        int batchSize = hits.size();
                        // Delegar el procesamiento del batch a procesarHitsBatch
                        processHitsBatch(hits, activeByKey, seenIds, seenCves, countersByAgent, infraCredId);
                        processedTotal += batchSize;

                        // Enviar progreso vía SSE
                        long totalForProgress = remoteNewTotal > 0 ? remoteNewTotal : 1; // Evitar división por cero
                        emitter.send(SseEmitter.event().name("progress").data(Map.of(
                                "processed", processedTotal,
                                "total", totalForProgress,
                                "percent", (int)((double)processedTotal / totalForProgress * 100),
                                "taskId", taskId
                        )));
                        log.debug("Progreso: {}/{}", processedTotal, totalForProgress);

                        // Actualizar lastSortValues / el cursor de paginación (search_after) para la siguiente iteración
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

        // 5. Registrar transiciones de estado por CVE en la línea de tiempo (agregado entre agentes y paquetes):
        //    la línea de tiempo guarda una sola vez cada CVE, ACTIVE si al menos un agente lo tiene
        //    y RESOLVED si ya ningún agente lo tiene. No se repite por agente ni por paquete.
        Map<String, VulnerabilityEntity> representativeByCve = new HashMap<>();
        for (VulnerabilityEntity vuln : activeByKey.values()) {
            representativeByCve.putIfAbsent(buildCveKey(vuln.getCve()), vuln);
        }

        // 5.1. CVEs que pasaron a estar activos (no estaban antes en la sincronización)
        Set<String> newlyActiveCves = new HashSet<>(seenCves);
        newlyActiveCves.removeAll(previousActiveCves);
        for (String cveKey : newlyActiveCves) {
            VulnerabilityEntity rep = representativeByCve.get(cveKey);
            if (rep != null) {
                timelineService.registerCveEvent(rep.getCve(), infraCredId,
                        rep.getSeverity(), rep.getCvss3Score(), "ACTIVE");
            }
        }

        // 5.2. Conciliación de estados (RESOLVED): si se usó FULL SYNC, se resuelven las vulnerabilidades
        //      que no aparecieron en la sincronización: un evento RESOLVED por CVE y se ELIMINAN las filas
        //      de active_vulnerabilities (la tabla solo conserva las activas).
        if (executeFullQuery) {
            Set<String> resolvedCves = new HashSet<>(previousActiveCves);
            resolvedCves.removeAll(seenCves);
            Set<String> processedResolved = new HashSet<>();
            List<Long> resolvedIds = new ArrayList<>();
            for (VulnerabilityEntity vuln : currentlyActive) {
                String cveKey = buildCveKey(vuln.getCve());
                if (resolvedCves.contains(cveKey)) {
                    if (processedResolved.add(cveKey)) {
                        timelineService.registerCveEvent(vuln.getCve(), infraCredId,
                                vuln.getSeverity(), vuln.getCvss3Score(), "RESOLVED");
                    }
                    resolvedIds.add(vuln.getId());
                }
            }
            if (!resolvedIds.isEmpty()) {
                vulnerabilityRepository.deleteAllByIdInBatch(resolvedIds);
                log.info("Se resolvieron {} vulnerabilidades legítimamente por ausencia (Full Sync)", resolvedIds.size());
            }
        } else {
            log.info("Sincronización incremental finalizada. Se omitió la resolución por ausencia para proteger registros históricos antiguos.");
        }

        // IAIIIIIAIII
        // =================================================================
        // 6. ACTUALIZAR LAS VISTAS MATERIALIZADAS AL FINALIZAR LA CARGA
        //La exigencia: El profesor indicó que las búsquedas más comunes (ej. "vulnerabilidades críticas") no debían consultar los miles de registros en tiempo real, sino que debían estar pre-calculadas usando procedimientos almacenados.
        //El momento exacto: Recalcó que este cálculo debía ocurrir "después de la carga" y quedar estático.
        // =================================================================
        log.info("Refrescando vistas materializadas de PostgreSQL...");
        vulnerabilityRepository.refreshVulnViews();
        log.info("Vistas materializadas actualizadas correctamente.");

        // Le avisamos al frontend que llegamos al 100% y cerramos la conexión limpiamente
        /*
        emitter.send(SseEmitter.event().name("complete").data(Map.of(
                "status", "FINISHED",
                "taskId", taskId
        )));
        emitter.complete(); 
        */
        log.info("Sincronización finalizada y conexión SSE cerrada con éxito.");

    } // <-- Aquí termina el método performSync 

    // ======================= PROCESAMIENTO DE BATCHES =======================
    /**
     * Procesa un lote de hits de vulnerabilidades desde Wazuh. 
     * Recibe bloques crudos de información (vulnerabilidades reportadas por Wazuh en formato JSON estructurado como mapas de Java)
     * <p>
     * 1. Extrae información de cada hit y crea o actualiza entidades VulnerabilityEntity.
     * 2. Evita duplicados dentro del mismo lote.
     * 3. Actualiza el mapa de vulnerabilidades activas y el conjunto de IDs vistas.
     * 4. Cuenta vulnerabilidades por agente y severidad para snapshots.
     * 5. Acumula los CVEs vistos (a nivel CVE) para registrar las transiciones de la línea de tiempo al final.
     * <p>
     * @param hits Lista de hits desde Wazuh.
     * @param activeByKey Mapa de vulnerabilidades activas por clave única (cve|agentId|packageName).
     * @param seenIds Conjunto de IDs de vulnerabilidades vistas durante esta sincronización.
     * @param seenCves Conjunto de CVEs vistos durante esta sincronización (a nivel CVE, sin repetir por agente ni paquete).
     * @param countersByAgent Mapa de contadores de snapshots por agente.
     */
    @SuppressWarnings("unchecked")
    private void processHitsBatch(List<Map<String, Object>> hits,
                                  Map<String, VulnerabilityEntity> activeByKey,
                                  Set<Long> seenIds,
                                  Set<String> seenCves,
                                  Map<Long, SnapshotCounter> countersByAgent,
                                  Long infraCredId) {
        // Listas para guardar vulnerabilidades que se crearán o actualizarán en la base de datos
        List<VulnerabilityEntity> toSave = new ArrayList<>();
        List<VulnerabilityEntity> toUpdate = new ArrayList<>();
        Set<String> processedKeys = new HashSet<>(); // Set para evitar duplicados dentro del lote actual

        for (Map<String, Object> hit : hits) {
            try {
                // Subestructuras de datos de Wazuh (del JSON crudo convertido a Map)
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
                // CVE visto durante esta sincronización (a nivel CVE, sin repetir por agente ni paquete)
                seenCves.add(buildCveKey(cve));

                Double cvssScore = extractCvssScore(v);
                LocalDateTime detectedAt = parseDateTime(v.get("detected_at"));

                // --- Buscar si ya existe en el mapa de activas (vienen de BD) ---
                VulnerabilityEntity existingActive = activeByKey.get(key);

                if (existingActive != null) {
                    // =================================================================
                    // CASO 1: Vulnerabilidad ya activa -> Actualizar datos mutables
                    // =================================================================
                    updateExistingVulnerability(existingActive, severity, cvssScore, underEvaluation, ctiReference,
                            pkgVersion, pkgType, pkgDescription);
                    toUpdate.add(existingActive);
                    seenIds.add(existingActive.getId());

                    // (No requiere evento de Timeline porque no cambia de estado)
                } else {
                    // =================================================================
                    // CASO 2: Vulnerabilidad nueva o reactivada en este agente -> insertar.
                    // active_vulnerabilities solo guarda las activas: si no está en el mapa de
                    // activas se crea de cero. El evento de la línea de tiempo se registra al
                    // final del sync mediante la diferencia de conjuntos de CVEs.
                    // =================================================================
                    VulnerabilityEntity entity = new VulnerabilityEntity();
                    entity.setCve(cve);
                    entity.setAgentId(agentIdNum);
                    entity.setInfrastructureCredentialsId(infraCredId);
                    entity.setPackageName(pkgName);
                    entity.setPackageVersion(pkgVersion);
                    entity.setPackageType(pkgType);
                    entity.setSeverity(severity);
                    entity.setUnderEvaluation(underEvaluation != null ? underEvaluation : false);
                    entity.setCtiReference(ctiReference);
                    entity.setDescription(pkgDescription);
                    entity.setCvss3Score(cvssScore);
                    entity.setDetectionTime(detectedAt);
                    entity.setLastSync(LocalDateTime.now(ZoneOffset.UTC));

                    toSave.add(entity);
                }
            } catch (Exception e) {
                log.warn("Error procesando hit: {}", e.getMessage(), e);
            }
        }

        // --- Guardar nuevas vulnerabilidades ---
        if (!toSave.isEmpty()) {
            List<VulnerabilityEntity> saved = vulnerabilityRepository.saveAll(toSave);
            for (VulnerabilityEntity v : saved) {
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
        existing.setLastSync(LocalDateTime.now(ZoneOffset.UTC));
    }

    private String buildKey(String cve, Long agentId, String packageName) {
        return cve + "|" + agentId + "|" + (packageName != null ? packageName : "");
    }

    private String buildCveKey(String cve) {
        return cve;
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