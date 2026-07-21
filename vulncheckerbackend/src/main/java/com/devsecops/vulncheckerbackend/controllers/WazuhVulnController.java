package com.devsecops.vulncheckerbackend.controllers;

import com.devsecops.vulncheckerbackend.dto.VulnerabilityRequest;
import com.devsecops.vulncheckerbackend.dto.WazuhCredentials;
import com.devsecops.vulncheckerbackend.entities.InfrastructureCredentialEntity;
import com.devsecops.vulncheckerbackend.repositories.InfrastructureCredentialRepository;
import com.devsecops.vulncheckerbackend.repositories.VulnerabilityRepository;
import com.devsecops.vulncheckerbackend.services.WazuhService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/vulns")
public class WazuhVulnController {

    private static final Logger log = LoggerFactory.getLogger(WazuhVulnController.class);

    private final WazuhService wazuhService;
    private final InfrastructureCredentialRepository infraRepo;
    private final VulnerabilityRepository vulnerabilityRepository;

    // Almacena los emisores SSE activos, indexados por taskId
    private final ConcurrentHashMap<String, SseEmitter> emitters = new ConcurrentHashMap<>();

    public WazuhVulnController(WazuhService wazuhService,
                               InfrastructureCredentialRepository infraRepo,
                               VulnerabilityRepository vulnerabilityRepository) {
        this.wazuhService = wazuhService;
        this.infraRepo = infraRepo;
        this.vulnerabilityRepository = vulnerabilityRepository;
    }

    // ======================= HELPER =======================
    private WazuhCredentials buildCredentialsFromRequest(VulnerabilityRequest request) {
        InfrastructureCredentialEntity credEntity = infraRepo.findById(request.getInfrastructureCredentialId())
                .orElseThrow(() -> new RuntimeException("Credencial no encontrada"));
        return new WazuhCredentials(
                request.getIp(),
                credEntity.getSshUser(),
                credEntity.getSshPassword(),
                credEntity.getWazuhUser(),
                credEntity.getWazuhPassword()
        );
    }

    // ======================= HELPER =======================
    private String[] parseBasicAuth(String auth) {
        if (auth == null || !auth.startsWith("Basic ")) {
            throw new IllegalArgumentException("Invalid Authorization header");
        }
        String decoded = new String(Base64.getDecoder().decode(auth.replace("Basic ", "").trim()));
        String[] parts = decoded.split(":", 2);
        if (parts.length < 2) {
            throw new IllegalArgumentException("Invalid credentials format in Authorization header");
        }
        return parts;
    }

    // ======================= ENDPOINTS LEGACY (CONSULTA DIRECTA) =======================
    // Se mantienen exactamente igual que en tu versión original
    @GetMapping("/{sshHost}/{sshUser}/{sshPassword}/all")
    public ResponseEntity<Map<String, Object>> getAllLegacy(
            @PathVariable String sshHost,
            @PathVariable String sshUser,
            @PathVariable String sshPassword,
            @RequestHeader("Authorization") String auth) throws Exception {
        String[] parts = parseBasicAuth(auth);
        WazuhCredentials creds = new WazuhCredentials(sshHost, sshUser, sshPassword, parts[0], parts[1]);
        return ResponseEntity.ok(wazuhService.getAllVulnerabilities(creds, 100, 0));
    }

    @GetMapping("/{sshHost}/{sshUser}/{sshPassword}/top/{limit}")
    public ResponseEntity<Map<String, Object>> getTop(
            @PathVariable String sshHost,
            @PathVariable String sshUser,
            @PathVariable String sshPassword,
            @RequestHeader("Authorization") String auth,
            @PathVariable int limit) throws Exception {
        String[] parts = parseBasicAuth(auth);
        WazuhCredentials creds = new WazuhCredentials(sshHost, sshUser, sshPassword, parts[0], parts[1]);
        return ResponseEntity.ok(wazuhService.getTopVulnerabilities(creds, limit));
    }

    @GetMapping("/{sshHost}/{sshUser}/{sshPassword}/critical")
    public ResponseEntity<Map<String, Object>> getCritical(
            @PathVariable String sshHost,
            @PathVariable String sshUser,
            @PathVariable String sshPassword,
            @RequestHeader("Authorization") String auth) throws Exception {
        String[] parts = parseBasicAuth(auth);
        WazuhCredentials creds = new WazuhCredentials(sshHost, sshUser, sshPassword, parts[0], parts[1]);
        return ResponseEntity.ok(wazuhService.getCriticalVulnerabilities(creds));
    }

    @GetMapping("/{sshHost}/{sshUser}/{sshPassword}/severity/{severity}")
    public ResponseEntity<Map<String, Object>> getBySeverity(
            @PathVariable String sshHost,
            @PathVariable String sshUser,
            @PathVariable String sshPassword,
            @RequestHeader("Authorization") String auth,
            @PathVariable String severity,
            @RequestParam(defaultValue = "100") int limit) throws Exception {
        String[] parts = parseBasicAuth(auth);
        WazuhCredentials creds = new WazuhCredentials(sshHost, sshUser, sshPassword, parts[0], parts[1]);
        return ResponseEntity.ok(wazuhService.getVulnerabilitiesBySeverity(creds, severity, limit));
    }

    @GetMapping("/{sshHost}/{sshUser}/{sshPassword}/cve/{cve}")
    public ResponseEntity<Map<String, Object>> getByCve(
            @PathVariable String sshHost,
            @PathVariable String sshUser,
            @PathVariable String sshPassword,
            @RequestHeader("Authorization") String auth,
            @PathVariable String cve) throws Exception {
        String[] parts = parseBasicAuth(auth);
        WazuhCredentials creds = new WazuhCredentials(sshHost, sshUser, sshPassword, parts[0], parts[1]);
        return ResponseEntity.ok(wazuhService.getVulnerabilitiesByCve(creds, cve));
    }

    @GetMapping("/{sshHost}/{sshUser}/{sshPassword}/agent/{agentId}")
    public ResponseEntity<Map<String, Object>> getByAgent(
            @PathVariable String sshHost,
            @PathVariable String sshUser,
            @PathVariable String sshPassword,
            @RequestHeader("Authorization") String auth,
            @PathVariable String agentId,
            @RequestParam(defaultValue = "100") int limit) throws Exception {
        String[] parts = parseBasicAuth(auth);
        WazuhCredentials creds = new WazuhCredentials(sshHost, sshUser, sshPassword, parts[0], parts[1]);
        return ResponseEntity.ok(wazuhService.getVulnerabilitiesByAgent(creds, agentId, limit));
    }

    @GetMapping("/{sshHost}/{sshUser}/{sshPassword}/summary")
    public ResponseEntity<Map<String, Object>> getSummary(
            @PathVariable String sshHost,
            @PathVariable String sshUser,
            @PathVariable String sshPassword,
            @RequestHeader("Authorization") String auth) throws Exception {
        String[] parts = parseBasicAuth(auth);
        WazuhCredentials creds = new WazuhCredentials(sshHost, sshUser, sshPassword, parts[0], parts[1]);
        return ResponseEntity.ok(wazuhService.getVulnerabilitiesSummary(creds));
    }

    // ======================= ENDPOINTS PARA SINCRONIZACIÓN INCREMENTAL Y SSE =======================

    /**
     * Devuelve el número total de vulnerabilidades locales (activas o no).
     * Usado por el frontend para mostrar el progreso.
     */
    @GetMapping("/count-local")
    public ResponseEntity<Map<String, Long>> getLocalCount() {
        long count = vulnerabilityRepository.count();
        log.info("Consulta de conteo local: {}", count);
        return ResponseEntity.ok(Map.of("count", count));
    }

    /**
     * Devuelve la cantidad de vulnerabilidades NUEVAS en Wazuh desde la última sincronización.
     * El frontend usa este valor para mostrar el total esperado y decidir si iniciar la sincronización.
     */
    @PostMapping("/remote-new-count")
    public ResponseEntity<Map<String, Long>> getRemoteNewCount(@RequestBody VulnerabilityRequest request) throws Exception {
        WazuhCredentials credentials = buildCredentialsFromRequest(request);
        LocalDateTime lastSync = vulnerabilityRepository.findMaxLastSync();
        long newCount = wazuhService.getRemoteNewCount(credentials, lastSync);
        log.info("Nuevas vulnerabilidades remotas desde {}: {}", lastSync, newCount);
        return ResponseEntity.ok(Map.of("newCount", newCount));
    }

    /**
     * Inicia una sincronización incremental.
     * - Si no hay novedades, responde inmediatamente con alreadySynced=true.
     * - Si hay novedades, crea un taskId, un SseEmitter, lanza la tarea asíncrona y devuelve el taskId.
     */
    @PostMapping("/consume")
    public ResponseEntity<Map<String, Object>> consumeAll(@RequestBody VulnerabilityRequest request) throws Exception {
        log.info(">>> consumeAll llamado con ID: {}", request.getInfrastructureCredentialId());

        WazuhCredentials credentials = buildCredentialsFromRequest(request);
        /*
        LocalDateTime lastSync = vulnerabilityRepository.findMaxLastSync();
        long newCount = wazuhService.getRemoteNewCount(credentials, lastSync);

        if (newCount == 0) {
            log.info("No hay vulnerabilidades nuevas. Sincronización no necesaria.");
            return ResponseEntity.ok(Map.of(
                    "alreadySynced", true,
                    "message", "Ya está sincronizado (no hay vulnerabilidades nuevas)"
            ));
        }
        */

        String taskId = UUID.randomUUID().toString();
        SseEmitter emitter = new SseEmitter(300_000L); // 5 minutos de timeout
        emitters.put(taskId, emitter);
        emitter.onCompletion(() -> emitters.remove(taskId));
        emitter.onTimeout(() -> emitters.remove(taskId));
        emitter.onError((e) -> emitters.remove(taskId));

        wazuhService.syncAllVulnerabilitiesMasive(credentials, taskId, emitter);

        return ResponseEntity.accepted().body(Map.of(
                "taskId", taskId,
                "status", "processing",
                "message", "Sincronización incremental iniciada"
        ));
    }

    /**
     * Endpoint SSE para recibir eventos de progreso.
     * El frontend se conecta a /api/vulns/progress/{taskId}
     */
    @GetMapping("/progress/{taskId}")
    public SseEmitter streamProgress(@PathVariable String taskId) {
        SseEmitter emitter = emitters.get(taskId);
        if (emitter == null) {
            // Si no existe (por ejemplo, por reinicio), se crea uno nuevo pero probablemente la tarea ya no está viva.
            // No obstante, se crea para no romper la conexión.
            emitter = new SseEmitter(300_000L);
            emitters.put(taskId, emitter);
            emitter.onCompletion(() -> emitters.remove(taskId));
            emitter.onTimeout(() -> emitters.remove(taskId));
            log.warn("Se creó un nuevo emitter para una tarea que posiblemente no tenga tarea asociada");
        }
        return emitter;
    }

    // ======================= MANEJO DE ERRORES GLOBAL =======================
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleError(Exception e) {
        log.error("Excepción no capturada: ", e);
        String customMessage = e.getMessage();

        if (e.getMessage() != null && e.getMessage().contains("timeout: socket is not established")) {
            customMessage = "No se pudo establecer conexión SSH (Timeout). Verifica que la IP sea correcta y el puerto 22 esté abierto.";
        } else if (e.getMessage() != null && e.getMessage().contains("Auth fail")) {
            customMessage = "Credenciales SSH incorrectas.";
        } else if (e.getMessage() != null && e.getMessage().contains("Credencial no encontrada")) {
            customMessage = "Credencial de infraestructura no encontrada.";
        }

        return ResponseEntity.status(500).body(Map.of(
                "error", e.getClass().getSimpleName(),
                "message", customMessage != null ? customMessage : "Error desconocido en el servidor"
        ));
    }
}