package com.devsecops.vulncheckerbackend.controllers;

import com.devsecops.vulncheckerbackend.dto.AgentRequest;
import com.devsecops.vulncheckerbackend.entities.AgentEntity;
import com.devsecops.vulncheckerbackend.services.AgentService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/agents")
public class AgentController {

    private final AgentService agentService;

    public AgentController(AgentService agentService) {
        this.agentService = agentService;
    }

    @GetMapping
    public List<AgentEntity> getAll() {
        return agentService.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<AgentEntity> getById(@PathVariable Long id) {
        Optional<AgentEntity> agent = agentService.findById(id);
        return agent.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/wazuh/{wazuhAgentId}")
    public ResponseEntity<AgentEntity> getByWazuhAgentId(@PathVariable String wazuhAgentId) {
        Optional<AgentEntity> agent = agentService.findByWazuhAgentId(wazuhAgentId);
        return agent.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping
    public AgentEntity create(@RequestBody AgentRequest request) {
        AgentEntity agent = new AgentEntity();
        agent.setWazuhAgentId(request.getWazuhAgentId());
        agent.setName(request.getName());
        agent.setVersion(request.getVersion());
        agent.setOsType(request.getOsType());
        agent.setOsFullName(request.getOsFullName());
        agent.setOsPlataform(request.getOsPlataform());
        return agentService.save(agent);
    }

    @PutMapping("/{id}")
    public ResponseEntity<AgentEntity> update(@PathVariable Long id, @RequestBody AgentRequest request) {
        if (!agentService.findById(id).isPresent()) {
            return ResponseEntity.notFound().build();
        }
        AgentEntity agent = new AgentEntity();
        agent.setId(id);
        agent.setWazuhAgentId(request.getWazuhAgentId());
        agent.setName(request.getName());
        agent.setVersion(request.getVersion());
        agent.setOsType(request.getOsType());
        agent.setOsFullName(request.getOsFullName());
        agent.setOsPlataform(request.getOsPlataform());
        return ResponseEntity.ok(agentService.save(agent));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        if (!agentService.findById(id).isPresent()) {
            return ResponseEntity.notFound().build();
        }
        agentService.deleteById(id);
        return ResponseEntity.noContent().build();
    }
}