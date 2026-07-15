package com.devsecops.vulncheckerbackend.dto;

public class InfraCredentialRequest {
    private Long userId;
    private String name;
    private String sshUser;
    private String sshPassword;
    private String wazuhUser;
    private String wazuhPassword;

    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getSshUser() { return sshUser; }
    public void setSshUser(String sshUser) { this.sshUser = sshUser; }

    public String getSshPassword() { return sshPassword; }
    public void setSshPassword(String sshPassword) { this.sshPassword = sshPassword; }

    public String getWazuhUser() { return wazuhUser; }
    public void setWazuhUser(String wazuhUser) { this.wazuhUser = wazuhUser; }

    public String getWazuhPassword() { return wazuhPassword; }
    public void setWazuhPassword(String wazuhPassword) { this.wazuhPassword = wazuhPassword; }
}
