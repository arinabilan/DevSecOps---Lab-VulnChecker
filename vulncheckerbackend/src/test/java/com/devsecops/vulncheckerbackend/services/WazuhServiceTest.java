package com.devsecops.vulncheckerbackend.services;

import com.devsecops.vulncheckerbackend.config.SshTunnelManager;
import com.devsecops.vulncheckerbackend.dto.WazuhCredentials;
import com.devsecops.vulncheckerbackend.entities.AgentEntity;
import com.devsecops.vulncheckerbackend.repositories.AgentRepository;
import com.devsecops.vulncheckerbackend.repositories.VulnerabilityRepository;
import com.devsecops.vulncheckerbackend.repositories.VulnerabilitySnapshotRepository;
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

import java.time.LocalDateTime;
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

/*
    @Mock
    private VulnerabilityTimelineService timelineService;
*/

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
                snapshotRepository, agentRepository, directExecutor);//, timelineService);
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