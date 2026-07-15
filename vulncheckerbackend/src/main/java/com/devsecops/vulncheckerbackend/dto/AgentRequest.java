package com.devsecops.vulncheckerbackend.dto;

public class AgentRequest {
    private String wazuhAgentId;
    private String name;
    private String version;
    private String osType;
    private String osFullName;
    private String osPlataform;

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
}
