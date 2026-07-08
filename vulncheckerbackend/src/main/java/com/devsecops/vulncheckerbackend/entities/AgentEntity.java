package com.devsecops.vulncheckerbackend.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "agents")
public class AgentEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "wazuh_agent_id")
    private String wazuhAgentId;

    private String name;
    private String version;

    @Column(name = "os_type")
    private String osType;

    @Column(name = "os_full_name")
    private String osFullName;

    @Column(name = "os_plataform")
    private String osPlataform;  // typo del diagrama, se respeta

    @Column(name = "last_seen")
    private LocalDateTime lastSeen;

    public AgentEntity() {
    }

    // Getters y Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getWazuhAgentId() { return wazuhAgentId; }
    public void setWazuhAgentId(String wazuhAgentId) { this.wazuhAgentId = wazuhAgentId; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }

    public String getOsType() { return osType; }
    public void setOsType(String osType) { this.osType = osType; }

    public String getOsFullName() { return osFullName; }
    public void setOsFullName(String osFullName) { this.osFullName = osFullName; }

    public String getOsPlataform() { return osPlataform; }
    public void setOsPlataform(String osPlataform) { this.osPlataform = osPlataform; }

    public LocalDateTime getLastSeen() { return lastSeen; }
    public void setLastSeen(LocalDateTime lastSeen) { this.lastSeen = lastSeen; }
}