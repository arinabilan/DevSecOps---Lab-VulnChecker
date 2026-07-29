package com.devsecops.vulncheckerbackend.controllers;

import com.devsecops.vulncheckerbackend.entities.AgentEntity;
import com.devsecops.vulncheckerbackend.repositories.UserRepository;
import com.devsecops.vulncheckerbackend.services.AgentService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AgentController.class)
@AutoConfigureMockMvc(addFilters = false)
class AgentControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AgentService agentService;

    @MockitoBean
    private UserRepository userRepository;

    @MockitoBean
    private BCryptPasswordEncoder passwordEncoder;

    @Test
    void getAll_returnsAgentList() throws Exception {
        AgentEntity agent = new AgentEntity();
        agent.setId(1L);
        agent.setWazuhAgentId("001");
        when(agentService.findAll()).thenReturn(List.of(agent));

        mockMvc.perform(get("/api/agents"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(1))
                .andExpect(jsonPath("$[0].wazuhAgentId").value("001"));
    }

    @Test
    void getById_returnsAgentWhenFound() throws Exception {
        AgentEntity agent = new AgentEntity();
        agent.setId(1L);
        when(agentService.findById(1L)).thenReturn(Optional.of(agent));

        mockMvc.perform(get("/api/agents/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1));
    }

    @Test
    void getById_returns404WhenNotFound() throws Exception {
        when(agentService.findById(99L)).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/agents/99"))
                .andExpect(status().isNotFound());
    }

    @Test
    void getByWazuhAgentId_returnsAgentWhenFound() throws Exception {
        AgentEntity agent = new AgentEntity();
        agent.setId(1L);
        agent.setWazuhAgentId("001");
        when(agentService.findByWazuhAgentId("001")).thenReturn(Optional.of(agent));

        mockMvc.perform(get("/api/agents/wazuh/001"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.wazuhAgentId").value("001"));
    }

    @Test
    void getByWazuhAgentId_returns404WhenNotFound() throws Exception {
        when(agentService.findByWazuhAgentId("UNKNOWN")).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/agents/wazuh/UNKNOWN"))
                .andExpect(status().isNotFound());
    }

    @Test
    void create_persistsAndReturnsAgent() throws Exception {
        AgentEntity saved = new AgentEntity();
        saved.setId(1L);
        saved.setWazuhAgentId("002");
        when(agentService.save(any())).thenReturn(saved);

        mockMvc.perform(post("/api/agents")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"wazuhAgentId\":\"002\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1));
    }

    @Test
    void update_returnsUpdatedAgentWhenFound() throws Exception {
        AgentEntity existing = new AgentEntity();
        existing.setId(1L);
        when(agentService.findById(1L)).thenReturn(Optional.of(existing));
        AgentEntity updated = new AgentEntity();
        updated.setId(1L);
        updated.setName("Updated");
        when(agentService.save(any())).thenReturn(updated);

        mockMvc.perform(put("/api/agents/1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Updated\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Updated"));
    }

    @Test
    void update_returns404WhenNotFound() throws Exception {
        when(agentService.findById(99L)).thenReturn(Optional.empty());

        mockMvc.perform(put("/api/agents/99")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Updated\"}"))
                .andExpect(status().isNotFound());
    }

    @Test
    void delete_returns204WhenFound() throws Exception {
        when(agentService.findById(1L)).thenReturn(Optional.of(new AgentEntity()));

        mockMvc.perform(delete("/api/agents/1"))
                .andExpect(status().isNoContent());
    }

    @Test
    void delete_returns404WhenNotFound() throws Exception {
        when(agentService.findById(99L)).thenReturn(Optional.empty());

        mockMvc.perform(delete("/api/agents/99"))
                .andExpect(status().isNotFound());
    }
}
