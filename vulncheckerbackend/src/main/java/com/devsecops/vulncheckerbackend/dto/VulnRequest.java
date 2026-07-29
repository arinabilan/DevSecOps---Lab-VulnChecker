package com.devsecops.vulncheckerbackend.dto;

import java.time.LocalDateTime;

public class VulnRequest {
    private String cve;
    private Long agentId;
    private String packageName;
    private String packageVersion;
    private String packageType;
    private String severity;
    private String status;
    private Boolean underEvaluation;
    private String ctiReference;
    private String description;
    private Double cvss3Score;
    private LocalDateTime detectionTime;

    public String getCve() { return cve; }
    public void setCve(String cve) { this.cve = cve; }

    public Long getAgentId() { return agentId; }
    public void setAgentId(Long agentId) { this.agentId = agentId; }

    public String getPackageName() { return packageName; }
    public void setPackageName(String packageName) { this.packageName = packageName; }

    public String getPackageVersion() { return packageVersion; }
    public void setPackageVersion(String packageVersion) { this.packageVersion = packageVersion; }

    public String getPackageType() { return packageType; }
    public void setPackageType(String packageType) { this.packageType = packageType; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public Boolean getUnderEvaluation() { return underEvaluation; }
    public void setUnderEvaluation(Boolean underEvaluation) { this.underEvaluation = underEvaluation; }

    public String getCtiReference() { return ctiReference; }
    public void setCtiReference(String ctiReference) { this.ctiReference = ctiReference; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public Double getCvss3Score() { return cvss3Score; }
    public void setCvss3Score(Double cvss3Score) { this.cvss3Score = cvss3Score; }

    public LocalDateTime getDetectionTime() { return detectionTime; }
    public void setDetectionTime(LocalDateTime detectionTime) { this.detectionTime = detectionTime; }
}
