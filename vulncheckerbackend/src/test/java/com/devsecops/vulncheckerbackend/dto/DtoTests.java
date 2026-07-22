package com.devsecops.vulncheckerbackend.dto;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DtoTests {

    @Test
    void agentRequest_setsAndGetsAllFields() {
        AgentRequest dto = new AgentRequest();
        dto.setWazuhAgentId("001");
        dto.setName("agent-1");
        dto.setVersion("5.0.0");
        dto.setOsType("Linux");
        dto.setOsFullName("Ubuntu 22.04");
        dto.setOsPlataform("x86_64");

        assertEquals("001", dto.getWazuhAgentId());
        assertEquals("agent-1", dto.getName());
        assertEquals("5.0.0", dto.getVersion());
        assertEquals("Linux", dto.getOsType());
        assertEquals("Ubuntu 22.04", dto.getOsFullName());
        assertEquals("x86_64", dto.getOsPlataform());
    }

    @Test
    void vulnRequest_setsAndGetsAllFields() {
        VulnRequest dto = new VulnRequest();
        LocalDateTime now = LocalDateTime.now();
        dto.setCve("CVE-2026-0001");
        dto.setAgentId(1L);
        dto.setPackageName("openssl");
        dto.setPackageVersion("1.1.1");
        dto.setPackageType("deb");
        dto.setSeverity("High");
        dto.setStatus("Active");
        dto.setUnderEvaluation(true);
        dto.setCtiReference("https://nvd.nist.gov/");
        dto.setDescription("Test vuln");
        dto.setCvss3Score(7.5);
        dto.setDetectionTime(now);

        assertEquals("CVE-2026-0001", dto.getCve());
        assertEquals(1L, dto.getAgentId());
        assertEquals("openssl", dto.getPackageName());
        assertEquals("1.1.1", dto.getPackageVersion());
        assertEquals("deb", dto.getPackageType());
        assertEquals("High", dto.getSeverity());
        assertEquals("Active", dto.getStatus());
        assertTrue(dto.getUnderEvaluation());
        assertEquals("https://nvd.nist.gov/", dto.getCtiReference());
        assertEquals("Test vuln", dto.getDescription());
        assertEquals(7.5, dto.getCvss3Score());
        assertEquals(now, dto.getDetectionTime());
    }

    @Test
    void vulnerabilityFiltersDto_setsAndGetsAllFields() {
        VulnerabilityFiltersDto dto = new VulnerabilityFiltersDto();
        dto.setSeverities(List.of("Critical", "High"));
        dto.setAgentIds(List.of("001", "002"));
        dto.setOs("Linux");
        dto.setYear(2026);
        dto.setGroupName("web");
        dto.setPackageName("openssl");
        dto.setSeverity("High");
        dto.setScore(5.0);
        dto.setAgentId(1L);
        dto.setSearch("CVE");

        assertEquals(List.of("Critical", "High"), dto.getSeverities());
        assertEquals(List.of("001", "002"), dto.getAgentIds());
        assertEquals("Linux", dto.getOs());
        assertEquals(2026, dto.getYear());
        assertEquals("web", dto.getGroupName());
        assertEquals("openssl", dto.getPackageName());
        assertEquals("High", dto.getSeverity());
        assertEquals(5.0, dto.getScore());
        assertEquals(1L, dto.getAgentId());
        assertEquals("CVE", dto.getSearch());
    }

    @Test
    void vulnerabilityFiltersDto_severitiesAndAgentIdsMatch() {
        VulnerabilityFiltersDto dto = new VulnerabilityFiltersDto(List.of("Critical"), List.of("001"));
        assertEquals(List.of("Critical"), dto.severities());
        assertEquals(List.of("001"), dto.agentIds());
    }

    @Test
    void chartStatItemDto_holdsValues() {
        ChartStatItemDto item = new ChartStatItemDto("High", 50);
        assertEquals("High", item.name());
        assertEquals(50, item.value());
    }

    @Test
    void vulnerabilityChartsDto_holdsValues() {
        var item = new ChartStatItemDto("High", 50);
        VulnerabilityChartsDto dto = new VulnerabilityChartsDto(
                100L, List.of(item), List.of(item), List.of(item), List.of(item), List.of(item));
        assertEquals(100L, dto.total());
        assertEquals(1, dto.category().size());
        assertEquals(1, dto.severity().size());
        assertEquals(1, dto.cve().size());
        assertEquals(1, dto.packageStats().size());
        assertEquals(1, dto.agent().size());
    }
}
