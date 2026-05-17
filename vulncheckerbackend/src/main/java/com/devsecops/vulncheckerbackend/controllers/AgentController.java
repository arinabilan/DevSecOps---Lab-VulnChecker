package com.devsecops.vulncheckerbackend.controllers;

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
    public AgentEntity create(@RequestBody AgentEntity agent) {
        return agentService.save(agent);
    }

    @PutMapping("/{id}")
    public ResponseEntity<AgentEntity> update(@PathVariable Long id, @RequestBody AgentEntity agent) {
        if (!agentService.findById(id).isPresent()) {
            return ResponseEntity.notFound().build();
        }
        agent.setId(id);
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