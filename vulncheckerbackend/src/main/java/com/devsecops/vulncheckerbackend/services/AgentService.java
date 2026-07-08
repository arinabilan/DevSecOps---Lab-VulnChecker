package com.devsecops.vulncheckerbackend.services;

import com.devsecops.vulncheckerbackend.entities.AgentEntity;
import com.devsecops.vulncheckerbackend.repositories.AgentRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class AgentService {

    private final AgentRepository agentRepository;

    public AgentService(AgentRepository agentRepository) {
        this.agentRepository = agentRepository;
    }

    public List<AgentEntity> findAll() {
        return agentRepository.findAll();
    }

    public Optional<AgentEntity> findById(Long id) {
        return agentRepository.findById(id);
    }

    public Optional<AgentEntity> findByWazuhAgentId(String wazuhAgentId) {
        return agentRepository.findByWazuhAgentId(wazuhAgentId);
    }

    public AgentEntity save(AgentEntity agent) {
        return agentRepository.save(agent);
    }

    public void deleteById(Long id) {
        agentRepository.deleteById(id);
    }

    public AgentEntity findOrCreateByWazuhAgentId(String wazuhAgentId, String name, String version,
                                                  String osType, String osFullName, String osPlatform) {
        return findByWazuhAgentId(wazuhAgentId).orElseGet(() -> {
            AgentEntity newAgent = new AgentEntity();
            newAgent.setWazuhAgentId(wazuhAgentId);
            newAgent.setName(name);
            newAgent.setVersion(version);
            newAgent.setOsType(osType);
            newAgent.setOsFullName(osFullName);
            newAgent.setOsPlataform(osPlatform);
            newAgent.setLastSeen(null);
            return agentRepository.save(newAgent);
        });
    }
}