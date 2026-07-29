package com.devsecops.vulncheckerbackend.services;

import com.devsecops.vulncheckerbackend.entities.AgentEntity;
import com.devsecops.vulncheckerbackend.repositories.AgentRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AgentServiceTest {

    @Mock
    private AgentRepository agentRepository;

    @InjectMocks
    private AgentService service;

    @Test
    void findAll_returnsAllAgents() {
        List<AgentEntity> agents = List.of(new AgentEntity(), new AgentEntity());
        when(agentRepository.findAll()).thenReturn(agents);

        List<AgentEntity> result = service.findAll();

        assertEquals(2, result.size());
        verify(agentRepository).findAll();
    }

    @Test
    void findById_returnsAgentWhenFound() {
        AgentEntity agent = new AgentEntity();
        agent.setId(1L);
        when(agentRepository.findById(1L)).thenReturn(Optional.of(agent));

        Optional<AgentEntity> result = service.findById(1L);

        assertTrue(result.isPresent());
        assertEquals(1L, result.get().getId());
    }

    @Test
    void findById_returnsEmptyWhenNotFound() {
        when(agentRepository.findById(99L)).thenReturn(Optional.empty());

        Optional<AgentEntity> result = service.findById(99L);

        assertTrue(result.isEmpty());
    }

    @Test
    void findByWazuhAgentId_returnsAgentWhenFound() {
        AgentEntity agent = new AgentEntity();
        agent.setWazuhAgentId("001");
        when(agentRepository.findByWazuhAgentId("001")).thenReturn(Optional.of(agent));

        Optional<AgentEntity> result = service.findByWazuhAgentId("001");

        assertTrue(result.isPresent());
        assertEquals("001", result.get().getWazuhAgentId());
    }

    @Test
    void save_persistsAndReturnsAgent() {
        AgentEntity agent = new AgentEntity();
        agent.setWazuhAgentId("002");
        when(agentRepository.save(agent)).thenReturn(agent);

        AgentEntity result = service.save(agent);

        assertEquals("002", result.getWazuhAgentId());
        verify(agentRepository).save(agent);
    }

    @Test
    void deleteById_delegatesToRepository() {
        service.deleteById(5L);

        verify(agentRepository).deleteById(5L);
    }

    @Test
    void findOrCreateByWazuhAgentId_returnsExistingAgentWhenFound() {
        AgentEntity existing = new AgentEntity();
        existing.setId(1L);
        existing.setWazuhAgentId("001");
        when(agentRepository.findByWazuhAgentId("001")).thenReturn(Optional.of(existing));

        AgentEntity result = service.findOrCreateByWazuhAgentId("001", "Agent1", "5.0", "Linux", "Ubuntu 22.04", "ubuntu");

        assertSame(existing, result);
        verify(agentRepository, never()).save(any());
    }

    @Test
    void findOrCreateByWazuhAgentId_createsNewAgentWhenNotFound() {
        when(agentRepository.findByWazuhAgentId("NEW-AGENT")).thenReturn(Optional.empty());
        AgentEntity saved = new AgentEntity();
        saved.setId(2L);
        saved.setWazuhAgentId("NEW-AGENT");
        when(agentRepository.save(any())).thenReturn(saved);

        AgentEntity result = service.findOrCreateByWazuhAgentId("NEW-AGENT", "NewAgent", "6.0", "Windows", "Windows 10", "windows");

        assertNotNull(result);
        assertEquals("NEW-AGENT", result.getWazuhAgentId());
        verify(agentRepository).save(any());
    }
}
