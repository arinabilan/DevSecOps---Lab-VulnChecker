package com.devsecops.vulncheckerbackend.dto;

import java.time.LocalDateTime;

public class IntervalDTO {
    private String status;
    private LocalDateTime startDate;
    private LocalDateTime endDate;

    public IntervalDTO() {}

    public IntervalDTO(String status, LocalDateTime startDate, LocalDateTime endDate) {
        this.status = status;
        this.startDate = startDate;
        this.endDate = endDate;
    }

    // Getters y Setters
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public LocalDateTime getStartDate() { return startDate; }
    public void setStartDate(LocalDateTime startDate) { this.startDate = startDate; }

    public LocalDateTime getEndDate() { return endDate; }
    public void setEndDate(LocalDateTime endDate) { this.endDate = endDate; }
}