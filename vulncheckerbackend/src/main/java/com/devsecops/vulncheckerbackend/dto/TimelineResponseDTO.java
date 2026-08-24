package com.devsecops.vulncheckerbackend.dto;

import java.util.List;

public class TimelineResponseDTO {
    private String cve;
    private String severity;
    private String packageName;
    private String packageType;
    private Double cvss3Score;
    private List<IntervalDTO> timeline;

    public TimelineResponseDTO() {}

    // Getters y Setters
    public String getCve() { return cve; }
    public void setCve(String cve) { this.cve = cve; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getPackageName() { return packageName; }
    public void setPackageName(String packageName) { this.packageName = packageName; }

    public String getPackageType() { return packageType; }
    public void setPackageType(String packageType) { this.packageType = packageType; }

    public Double getCvss3Score() { return cvss3Score; }
    public void setCvss3Score(Double cvss3Score) { this.cvss3Score = cvss3Score; }

    public List<IntervalDTO> getTimeline() { return timeline; }
    public void setTimeline(List<IntervalDTO> timeline) { this.timeline = timeline; }
}