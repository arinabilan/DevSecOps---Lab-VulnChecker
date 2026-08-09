package com.devsecops.vulncheckerbackend.services;

import com.devsecops.vulncheckerbackend.config.SshTunnelManager;
import com.devsecops.vulncheckerbackend.dto.WazuhCredentials;
import com.devsecops.vulncheckerbackend.entities.AgentEntity;
import com.devsecops.vulncheckerbackend.entities.VulnerabilityEntity;
import com.devsecops.vulncheckerbackend.repositories.AgentRepository;
import com.devsecops.vulncheckerbackend.repositories.VulnerabilityRepository;
import com.devsecops.vulncheckerbackend.repositories.VulnerabilitySnapshotRepository;
import com.devsecops.vulncheckerbackend.support.TestDataFactory;
import com.jcraft.jsch.Session;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executor;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class WazuhServiceTest {

    @Mock
    private SshTunnelManager tunnelManager;

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private VulnerabilityRepository vulnerabilityRepository;

    @Mock
    private VulnerabilitySnapshotRepository snapshotRepository;

    @Mock
    private AgentRepository agentRepository;

    @Mock
    private VulnerabilityTimelineService timelineService;

    @Mock
    private InfrastructureCredentialService infrastructureCredentialService;

    @Mock
    private Session session;

    private WazuhService service;
    private WazuhService spyService;

    private static final WazuhCredentials CREDS = new WazuhCredentials(
            "10.0.0.1", "root", "ssh-pass", "api-user", "api-pass"
    );

    @BeforeEach
    void setUp() {
        Executor directExecutor = Runnable::run;
        // Crear el servicio real con los mocks
        WazuhService realService = new WazuhService(tunnelManager, restTemplate, vulnerabilityRepository,
                snapshotRepository, agentRepository, infrastructureCredentialService, timelineService, directExecutor);
        // Espiar el servicio real
        spyService = spy(realService);
        this.service = spyService; // Para los tests que usen service directamente
    }

    @Test
    void getAllVulnerabilities_queriesWazuhWithoutPersistingSnapshots() throws Exception {
        when(tunnelManager.openTunnel("10.0.0.1", 22, "root", "ssh-pass")).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);
        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(searchResponse(List.of(singleHit("CVE-2026-1000", "High", "001", "openssl", List.of(1700000001L, "abc"))))));

        Map<String, Object> result = service.getAllVulnerabilities(CREDS, 6000, 10);

        assertNotNull(result);
        verifyNoInteractions(vulnerabilityRepository);
        verifyNoInteractions(snapshotRepository);
        verify(tunnelManager).closeTunnel(session);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<HttpEntity<String>> requestCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).exchange(
                anyString(),
                eq(HttpMethod.POST),
                requestCaptor.capture(),
                any(ParameterizedTypeReference.class)
        );
        String queryBody = requestCaptor.getValue().getBody();
        assertNotNull(queryBody);
        assertTrue(queryBody.contains("\"from\": 10"));
        assertTrue(queryBody.contains("\"size\": 5000"));
    }

    @Test
    void getAllVulnerabilities_closesTunnelWhenSearchFails() throws Exception {
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);
        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                any(ParameterizedTypeReference.class)
        )).thenThrow(new RuntimeException("network error"));

        assertThrows(RuntimeException.class, () -> service.getAllVulnerabilities(CREDS, 100, 0));
        verify(tunnelManager).closeTunnel(session);
    }

    @Test
    void getTopVulnerabilities_delegatesToGetAll() throws Exception {
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of("top", "data")));

        Map<String, Object> result = service.getTopVulnerabilities(CREDS, 5);

        assertEquals("data", result.get("top"));
        verify(tunnelManager).closeTunnel(session);
    }

    @Test
    void getCriticalVulnerabilities_delegatesToBySeverity() throws Exception {
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of("crit", "data")));

        Map<String, Object> result = service.getCriticalVulnerabilities(CREDS);

        assertEquals("data", result.get("crit"));
        verify(tunnelManager).closeTunnel(session);
    }

    @Test
    void getVulnerabilitiesBySeverity_queriesWithMatch() throws Exception {
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of("severity", "high")));

        Map<String, Object> result = service.getVulnerabilitiesBySeverity(CREDS, "high", 50);

        assertEquals("high", result.get("severity"));
        verify(tunnelManager).closeTunnel(session);
    }

    @Test
    void getVulnerabilitiesByAgent_queriesWithTerm() throws Exception {
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of("agent", "001")));

        Map<String, Object> result = service.getVulnerabilitiesByAgent(CREDS, "001", 100);

        assertEquals("001", result.get("agent"));
        verify(tunnelManager).closeTunnel(session);
    }

    @Test
    void getVulnerabilitiesByCve_queriesWithMatch() throws Exception {
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of("cve", "CVE-2026-0001")));

        Map<String, Object> result = service.getVulnerabilitiesByCve(CREDS, "CVE-2026-0001");

        assertEquals("CVE-2026-0001", result.get("cve"));
        verify(tunnelManager).closeTunnel(session);
    }

    @Test
    void getVulnerabilitiesSummary_queriesWithAggs() throws Exception {
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of("aggregations", Map.of("by_severity", "data"))));

        Map<String, Object> result = service.getVulnerabilitiesSummary(CREDS);

        assertEquals("data", ((Map<?, ?>) result.get("aggregations")).get("by_severity"));
        verify(tunnelManager).closeTunnel(session);
    }

    @Test
    void getRemoteNewCount_returnsCountWhenSinceIsNull() throws Exception {
        when(tunnelManager.openTunnel("10.0.0.1", 22, "root", "ssh-pass")).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);
        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of("count", 99)));

        long count = service.getRemoteNewCount(CREDS, null);

        assertEquals(99L, count);
        verify(tunnelManager).closeTunnel(session);
        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        verify(restTemplate).exchange(urlCaptor.capture(), eq(HttpMethod.POST), any(), any(ParameterizedTypeReference.class));
        assertTrue(urlCaptor.getValue().contains("_count"));
    }

    @Test
    void getRemoteNewCount_returnsCountWhenSinceIsNotNull() throws Exception {
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of("count", 7)));

        long count = service.getRemoteNewCount(CREDS, LocalDateTime.of(2026, 1, 1, 0, 0));

        assertEquals(7L, count);
        verify(tunnelManager).closeTunnel(session);
    }

    @Test
    void performSync_processesOnePageAndSavesSnapshots() throws Exception {
        when(vulnerabilityRepository.findMaxLastSync()).thenReturn(LocalDateTime.of(2026, 1, 1, 0, 0));

        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);

        Map<String, Object> hitResponse = searchResponse(List.of(singleHit("CVE-2026-1000", "High", "001", "openssl", List.of(1700000001L, "abc"))));
        Map<String, Object> emptyResponse = searchResponse(List.of());

        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of("count", 99)))
          .thenReturn(ResponseEntity.ok(hitResponse))
          .thenReturn(ResponseEntity.ok(emptyResponse));

        AgentEntity agent = new AgentEntity();
        agent.setId(1L);
        agent.setWazuhAgentId("001");
        when(agentRepository.findByWazuhAgentId("001")).thenReturn(Optional.empty());
        when(agentRepository.save(any())).thenReturn(agent);
        when(vulnerabilityRepository.saveAll(any())).thenAnswer(inv -> inv.getArgument(0));

        SseEmitter emitter = mock(SseEmitter.class);

        service.syncAllVulnerabilitiesMasive(CREDS, "task-1", emitter);

        verify(vulnerabilityRepository).findMaxLastSync();
        verify(vulnerabilityRepository).findByInfrastructureCredentialsId(any());
        verify(tunnelManager, atLeast(2)).openTunnel(anyString(), eq(22), anyString(), anyString());
        verify(agentRepository).findByWazuhAgentId("001");
        verify(agentRepository).save(any());
        verify(vulnerabilityRepository).saveAll(any());
        // La línea de tiempo registra una sola vez el CVE nuevo (ACTIVE), no por agente
        verify(timelineService).registerCveEvent(eq("CVE-2026-1000"), any(), eq("High"), any(), eq("ACTIVE"));
        verify(tunnelManager, atLeast(2)).closeTunnel(any());
        verify(snapshotRepository).save(any());
        verify(emitter).complete();
    }

    @Test
    void syncAllVulnerabilitiesMasive_sendsErrorOnFailure() throws Exception {
        when(vulnerabilityRepository.findMaxLastSync()).thenReturn(LocalDateTime.now());
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenThrow(new RuntimeException("network failure"));

        SseEmitter emitter = mock(SseEmitter.class);

        service.syncAllVulnerabilitiesMasive(CREDS, "task-2", emitter);

        verify(emitter).completeWithError(any(RuntimeException.class));
    }

    @Test
    void performSync_resolvesActiveVulnsNotFoundInWazuh() throws Exception {
        VulnerabilityEntity activeVuln = TestDataFactory.vulnerability(1L);
        when(vulnerabilityRepository.findMaxLastSync()).thenReturn(null);
        when(infrastructureCredentialService.getIdByWazuhCredentials(any())).thenReturn(0L);
        when(vulnerabilityRepository.findByInfrastructureCredentialsId(0L))
                .thenReturn(List.of(activeVuln));
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);

        Map<String, Object> emptyResponse = searchResponse(List.of());
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of("count", 0)))
          .thenReturn(ResponseEntity.ok(emptyResponse));

        SseEmitter emitter = mock(SseEmitter.class);
        service.performSync(CREDS, "task-3", emitter, true);

        // La vulnerabilidad que ya no aparece se elimina de active_vulnerabilities
        // y se registra una sola vez (por CVE, no por agente) el evento RESOLVED en el timeline.
        verify(timelineService).registerCveEvent(
                eq("CVE-2026-0001"), eq(0L), eq("High"), any(), eq("RESOLVED"));
        verify(vulnerabilityRepository).deleteAllByIdInBatch(anyList());
    }

    @Test
    void performSync_registersSingleActiveEventForCveAppearingInMultiplePackages() throws Exception {
        when(vulnerabilityRepository.findMaxLastSync()).thenReturn(null);
        when(infrastructureCredentialService.getIdByWazuhCredentials(any())).thenReturn(0L);
        when(vulnerabilityRepository.findByInfrastructureCredentialsId(0L)).thenReturn(List.of());
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);

        Map<String, Object> page1 = searchResponse(List.of(
                singleHit("CVE-2026-2000", "High", "001", "openssl", List.of(1700000001L, "a1")),
                singleHit("CVE-2026-2000", "High", "001", "libssl", List.of(1700000001L, "a2"))
        ));
        Map<String, Object> emptyResponse = searchResponse(List.of());
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of("count", 2)))
          .thenReturn(ResponseEntity.ok(page1))
          .thenReturn(ResponseEntity.ok(emptyResponse));

        AgentEntity agent = new AgentEntity();
        agent.setId(1L);
        agent.setWazuhAgentId("001");
        when(agentRepository.findByWazuhAgentId("001")).thenReturn(Optional.empty());
        when(agentRepository.save(any())).thenReturn(agent);
        when(vulnerabilityRepository.saveAll(any())).thenAnswer(inv -> inv.getArgument(0));

        service.performSync(CREDS, "task-4", mock(SseEmitter.class), true);

        // Mismo CVE en dos paquetes: se registra UNA sola vez (ACTIVE), sin importar el paquete
        verify(timelineService, times(1)).registerCveEvent(eq("CVE-2026-2000"), eq(0L), eq("High"), any(), eq("ACTIVE"));
        verify(timelineService, never()).registerCveEvent(eq("CVE-2026-2000"), eq(0L), eq("High"), any(), eq("RESOLVED"));
    }

    @Test
    void performSync_doesNotRegisterSpuriousEventsWhenCveMovesToAnotherPackage() throws Exception {
        VulnerabilityEntity activeVuln = TestDataFactory.vulnerability(1L); // CVE-2026-0001 en paquete openssl
        when(vulnerabilityRepository.findMaxLastSync()).thenReturn(null);
        when(infrastructureCredentialService.getIdByWazuhCredentials(any())).thenReturn(0L);
        when(vulnerabilityRepository.findByInfrastructureCredentialsId(0L))
                .thenReturn(List.of(activeVuln));
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);

        Map<String, Object> page1 = searchResponse(List.of(
                singleHit("CVE-2026-0001", "High", "001", "libssl", List.of(1700000001L, "b1"))
        ));
        Map<String, Object> emptyResponse = searchResponse(List.of());
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of("count", 1)))
          .thenReturn(ResponseEntity.ok(page1))
          .thenReturn(ResponseEntity.ok(emptyResponse));

        AgentEntity agent = new AgentEntity();
        agent.setId(1L);
        agent.setWazuhAgentId("001");
        when(agentRepository.findByWazuhAgentId("001")).thenReturn(Optional.empty());
        when(agentRepository.save(any())).thenReturn(agent);
        when(vulnerabilityRepository.saveAll(any())).thenAnswer(inv -> inv.getArgument(0));

        service.performSync(CREDS, "task-5", mock(SseEmitter.class), true);

        // El CVE sigue activo (cambió de paquete): no se registra ACTIVE ni RESOLVED espurios
        verify(timelineService, never()).registerCveEvent(any(), any(), any(), any(), any());
        verify(vulnerabilityRepository, never()).deleteAllByIdInBatch(anyList());
    }

    @Test
    void performSync_coversVariedHitProcessingBranches() throws Exception {
        when(vulnerabilityRepository.findMaxLastSync()).thenReturn(null);
        when(infrastructureCredentialService.getIdByWazuhCredentials(any())).thenReturn(0L);
        when(vulnerabilityRepository.findByInfrastructureCredentialsId(0L)).thenReturn(List.of());
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);

        List<Map<String, Object>> hits = List.of(
                // Agente en raíz (formato nuevo), scanner presente, SO solo con name, fecha epoch millis
                rawHit(fullSource("CVE-2026-3001", "medium", "002", Map.of("name", "Debian"), "openssl",
                        Map.of("base", 7.5), 1700000000000L, true, true)),
                // Duplicado exacto del anterior en el mismo lote
                rawHit(fullSource("CVE-2026-3001", "medium", "002", Map.of("name", "Debian"), "openssl",
                        Map.of("base", 7.5), 1700000000000L, true, true)),
                // Severity low, SO name+version, fecha epoch seconds, sin score (score nulo)
                rawHit(fullSource("CVE-2026-3002", "low", "003", Map.of("name", "Ubuntu", "version", "24.04"), "libssl",
                        null, 1700000001L, false, false)),
                // Severity desconocida (default) y score vacío (base nulo)
                rawHit(fullSource("CVE-2026-3006", "info", "007", Map.of("name", "Suse"), "openssh",
                        Map.of(), 1700000002L, false, false)),
                // Hit sin vulnerability -> omitido
                rawHit(Map.of("package", Map.of("name", "x"))),
                // Fecha inválida -> catch en parseDateTime
                rawHit(fullSource("CVE-2026-3003", "high", "004", Map.of("name", "CentOS"), "bash",
                        Map.of("base", 8.0), "not-a-date", false, false)),
                // score.base no numérico -> NumberFormatException
                rawHit(fullSource("CVE-2026-3004", "critical", "005", Map.of("name", "Alma"), "glibc",
                        Map.of("base", "abc"), 1700000003L, false, false)),
                // Severity null -> SnapshotCounter ignora
                rawHit(fullSource("CVE-2026-3005", null, "006", Map.of("name", "Rocky"), "curl",
                        Map.of("base", 5.0), 1700000004L, false, false))
        );
        Map<String, Object> page1 = searchResponse(hits);
        Map<String, Object> emptyResponse = searchResponse(List.of());
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of("count", 8)))
          .thenReturn(ResponseEntity.ok(page1))
          .thenReturn(ResponseEntity.ok(emptyResponse));

        AgentEntity agent = new AgentEntity();
        agent.setId(1L);
        when(agentRepository.findByWazuhAgentId(anyString())).thenReturn(Optional.empty());
        when(agentRepository.save(any())).thenReturn(agent);
        when(vulnerabilityRepository.saveAll(any())).thenAnswer(inv -> inv.getArgument(0));

        service.performSync(CREDS, "task-6", mock(SseEmitter.class), true);

        // Los 6 CVEs válidos vistos se registran una sola vez como ACTIVE
        verify(timelineService, times(6)).registerCveEvent(any(), eq(0L), any(), any(), eq("ACTIVE"));
        verify(vulnerabilityRepository).saveAll(anyList());
    }

    @Test
    void performSync_updatesExistingActiveVulnerabilities() throws Exception {
        when(vulnerabilityRepository.findMaxLastSync()).thenReturn(null);
        when(infrastructureCredentialService.getIdByWazuhCredentials(any())).thenReturn(0L);
        // Dos filas idénticas (mismo cve/agente/paquete) para cubrir la función de merge del toMap
        VulnerabilityEntity dup1 = TestDataFactory.vulnerability(1L);
        VulnerabilityEntity dup2 = TestDataFactory.vulnerability(2L);
        when(vulnerabilityRepository.findByInfrastructureCredentialsId(0L)).thenReturn(List.of(dup1, dup2));
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);

        Map<String, Object> page1 = searchResponse(List.of(
                singleHit("CVE-2026-0001", "High", "001", "openssl", List.of(1700000001L, "c1"))
        ));
        Map<String, Object> emptyResponse = searchResponse(List.of());
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of("count", 1)))
          .thenReturn(ResponseEntity.ok(page1))
          .thenReturn(ResponseEntity.ok(emptyResponse));

        AgentEntity agent = new AgentEntity();
        agent.setId(100L); // coincide con el agentId de las vulnerabilidades activas
        agent.setWazuhAgentId("001");
        when(agentRepository.findByWazuhAgentId("001")).thenReturn(Optional.of(agent));
        when(agentRepository.save(any())).thenReturn(agent);

        service.performSync(CREDS, "task-7", mock(SseEmitter.class), true);

        // Caso 1: la vulnerabilidad ya estaba activa -> solo se actualiza, sin evento de timeline
        verify(vulnerabilityRepository).saveAll(anyList());
        verify(timelineService, never()).registerCveEvent(any(), any(), any(), any(), any());
        verify(vulnerabilityRepository, never()).deleteAllByIdInBatch(anyList());
    }

    @Test
    void performSync_incrementalMode_skipsResolutionAndUsesRangeFilter() throws Exception {
        when(vulnerabilityRepository.findMaxLastSync()).thenReturn(LocalDateTime.of(2026, 1, 1, 0, 0));
        when(infrastructureCredentialService.getIdByWazuhCredentials(any())).thenReturn(0L);
        when(vulnerabilityRepository.findByInfrastructureCredentialsId(0L)).thenReturn(List.of());
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);

        // Respuesta con hits nulos -> termina paginación sin procesar
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of("count", 0)))
          .thenReturn(ResponseEntity.ok(Map.of("hits", Map.of())));

        service.performSync(CREDS, "task-8", mock(SseEmitter.class), false);

        verify(timelineService, never()).registerCveEvent(any(), any(), any(), any(), any());
        verify(vulnerabilityRepository, never()).deleteAllByIdInBatch(anyList());
    }

    @Test
    void syncAllVulnerabilitiesMasive_handlesCompleteSendFailure() throws Exception {
        when(vulnerabilityRepository.findMaxLastSync()).thenReturn(null);
        when(infrastructureCredentialService.getIdByWazuhCredentials(any())).thenReturn(0L);
        when(vulnerabilityRepository.findByInfrastructureCredentialsId(0L)).thenReturn(List.of());
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of("count", 0)))
          .thenReturn(ResponseEntity.ok(searchResponse(List.of())));

        SseEmitter emitter = mock(SseEmitter.class);
        doThrow(new IOException("boom")).when(emitter).send(any(SseEmitter.SseEventBuilder.class));

        service.syncAllVulnerabilitiesMasive(CREDS, "task-9", emitter);

        verify(emitter, never()).complete();
        verify(emitter, never()).completeWithError(any());
    }

    @Test
    void syncAllVulnerabilitiesMasive_handlesErrorSendFailure() throws Exception {
        when(vulnerabilityRepository.findMaxLastSync()).thenReturn(LocalDateTime.now());
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenThrow(new RuntimeException("network failure"));

        SseEmitter emitter = mock(SseEmitter.class);
        doThrow(new IOException("boom")).when(emitter).send(any(SseEmitter.SseEventBuilder.class));

        service.syncAllVulnerabilitiesMasive(CREDS, "task-10", emitter);

        verify(emitter, never()).complete();
        verify(emitter, never()).completeWithError(any());
    }

    private static Map<String, Object> fullSource(String cve, String severity, String agentId, Map<String, Object> os,
                                                  String pkgName, Object score, Object detectedAt, boolean rootAgent,
                                                  boolean withScanner) {
        Map<String, Object> vuln = new LinkedHashMap<>();
        vuln.put("id", cve);
        vuln.put("severity", severity);
        vuln.put("under_evaluation", false);
        if (score != null) vuln.put("score", score);
        if (detectedAt != null) vuln.put("detected_at", detectedAt);
        if (withScanner) vuln.put("scanner", Map.of("reference", "cti-ref"));

        Map<String, Object> agent = new LinkedHashMap<>();
        agent.put("id", agentId);
        agent.put("name", "agent-" + agentId);
        agent.put("version", "v5.0.0");
        if (os != null) {
            Map<String, Object> host = new LinkedHashMap<>();
            host.put("os", os);
            agent.put("host", host);
        }

        Map<String, Object> source = new LinkedHashMap<>();
        if (rootAgent) {
            source.put("agent", agent);
        } else {
            source.put("wazuh", Map.of("agent", agent));
        }
        if (pkgName != null) {
            source.put("package", Map.of("name", pkgName, "version", "1.0", "type", "deb"));
        }
        source.put("vulnerability", vuln);
        return source;
    }

    private static Map<String, Object> rawHit(Map<String, Object> source) {
        return Map.of("_id", "doc", "_source", source, "sort", List.of(1700000001L, "z"));
    }

    @Test
    void getRemoteNewCount_throwsWhenBodyMissingCount() throws Exception {
        when(tunnelManager.openTunnel(anyString(), eq(22), anyString(), anyString())).thenReturn(session);
        when(tunnelManager.getLocalPort(session)).thenReturn(36251);
        when(restTemplate.exchange(
                anyString(), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(Map.of()));

        assertThrows(RuntimeException.class, () -> service.getRemoteNewCount(CREDS, null));
        verify(tunnelManager).closeTunnel(session);
    }

    
    // ========== Métodos auxiliares (iguales) ==========
    private static Map<String, Object> searchResponse(List<Map<String, Object>> hits) {
        return Map.of("hits", Map.of("hits", hits));
    }

    private static Map<String, Object> singleHit(String cve, String severity, String agentId, String pkg, List<Object> sortValues) {
        // Estructura actualizada según el nuevo formato de Wazuh
        return Map.of(
                "_id", "doc_" + cve,
                "_source", Map.of(
                        "vulnerability", Map.of(
                                "id", cve,
                                "severity", severity,
                                "score", Map.of("base", 8.4),
                                "detected_at", "2026-01-10T10:00:00Z",
                                "under_evaluation", false
                        ),
                        "wazuh", Map.of(
                                "agent", Map.of(
                                        "id", agentId,
                                        "name", "agent-" + agentId,
                                        "version", "v5.0.0",
                                        "host", Map.of(
                                                "os", Map.of(
                                                        "name", "Ubuntu",
                                                        "platform", "linux",
                                                        "type", "linux",
                                                        "full", "Ubuntu 24.04"
                                                )
                                        )
                                )
                        ),
                        "package", Map.of(
                                "name", pkg,
                                "version", "1.0.0",
                                "type", "deb",
                                "description", "Package description"
                        )
                ),
                "sort", sortValues
        );
    }
}