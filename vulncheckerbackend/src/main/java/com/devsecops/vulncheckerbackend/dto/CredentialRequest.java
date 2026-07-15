package com.devsecops.vulncheckerbackend.dto;

public class CredentialRequest {
    private Long createdByUserId;
    private String usernameCredentials;
    private String passwordCredentials;

    public Long getCreatedByUserId() { return createdByUserId; }
    public void setCreatedByUserId(Long createdByUserId) { this.createdByUserId = createdByUserId; }

    public String getUsernameCredentials() { return usernameCredentials; }
    public void setUsernameCredentials(String usernameCredentials) { this.usernameCredentials = usernameCredentials; }

    public String getPasswordCredentials() { return passwordCredentials; }
    public void setPasswordCredentials(String passwordCredentials) { this.passwordCredentials = passwordCredentials; }
}
