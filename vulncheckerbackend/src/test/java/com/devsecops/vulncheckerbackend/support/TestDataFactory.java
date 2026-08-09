package com.devsecops.vulncheckerbackend.support;

import com.devsecops.vulncheckerbackend.dto.ReportSignatureRequest;
import com.devsecops.vulncheckerbackend.dto.VulnerabilityRequest;
import com.devsecops.vulncheckerbackend.entities.CredentialEntity;
import com.devsecops.vulncheckerbackend.entities.InfrastructureCredentialEntity;
import com.devsecops.vulncheckerbackend.entities.ReportSignatureEntity;
import com.devsecops.vulncheckerbackend.entities.UserEntity;
import com.devsecops.vulncheckerbackend.entities.VulnerabilityEntity;
import com.devsecops.vulncheckerbackend.entities.VulnerabilitySnapshotEntity;

import java.time.LocalDateTime;
import java.util.Base64;

public final class TestDataFactory {

    private TestDataFactory() {
    }

    public static UserEntity user(Long id) {
        UserEntity user = new UserEntity();
        user.setId(id);
        user.setFirstName("Admin");
        user.setPaternalLastName("Sistema");
        user.setMaternalLastName("Usach");
        user.setEmail("admin.seguridad@usach.cl");
        user.setPassword("admin123");
        user.setActive(true);  // <-- NUEVO: usuario activo por defecto en pruebas
        return user;
    }

    public static CredentialEntity credential(Long id, Long userId) {
        CredentialEntity credential = new CredentialEntity();
        credential.setId(id);
        credential.setCreatedByUserId(userId);
        credential.setUsernameCredentials("wazuh-user");
        credential.setPasswordCredentials("wazuh-pass");
        return credential;
    }

    public static InfrastructureCredentialEntity infrastructureCredential(Long id, Long userId) {
        InfrastructureCredentialEntity credential = new InfrastructureCredentialEntity();
        credential.setId(id);
        credential.setUserId(userId);
        credential.setName("Laboratorio");
        credential.setSshUser("root");
        credential.setSshPassword("ssh-pass");
        credential.setWazuhUser("wazuh-api");
        credential.setWazuhPassword("wazuh-pass");
        return credential;
    }

    public static VulnerabilityEntity vulnerability(Long id) {
        VulnerabilityEntity entity = new VulnerabilityEntity();
        entity.setId(id);
        entity.setAgentId(100L);
        entity.setCve("CVE-2026-0001");
        entity.setDescription("Example description");
        entity.setSeverity("High");
        entity.setCvss3Score(8.1);
        entity.setPackageName("openssl");
        entity.setPackageVersion("1.0.2");
        entity.setDetectionTime(LocalDateTime.of(2026, 1, 10, 9, 30));
        entity.setUnderEvaluation(false);
        entity.setCtiReference(null);
        entity.setPackageType("deb");
        return entity;
    }

    public static VulnerabilitySnapshotEntity snapshot(Long agentId, int critical, int high, int medium, int low) {
        VulnerabilitySnapshotEntity snapshot = new VulnerabilitySnapshotEntity();
        snapshot.setAgentId(agentId);
        snapshot.setCriticalCount(critical);
        snapshot.setHighCount(high);
        snapshot.setMediumCount(medium);
        snapshot.setLowCount(low);
        snapshot.setTotalCount(critical + high + medium + low);
        snapshot.setSnapshotDate(LocalDateTime.of(2026, 1, 10, 10, 0));
        return snapshot;
    }

    // Para mantener compatibilidad con tests antiguos que usen snapshot(String, ...)
    public static VulnerabilitySnapshotEntity snapshot(String agentId, int critical, int high, int medium, int low) {
        return snapshot(Long.parseLong(agentId), critical, high, medium, low);
    }

    public static ReportSignatureEntity reportSignature(String hash, String signature) {
        ReportSignatureEntity entity = new ReportSignatureEntity();
        entity.setId(1L);
        entity.setReportName("reporte-semanal");
        entity.setSha256Hash(hash);
        entity.setDigitalSignature(signature);
        entity.setSignedAt(LocalDateTime.of(2026, 1, 10, 11, 0));
        return entity;
    }

    public static ReportSignatureRequest reportSignatureRequest(String reportName, String hash) {
        ReportSignatureRequest request = new ReportSignatureRequest();
        request.setReportName(reportName);
        request.setSha256Hash(hash);
        return request;
    }

    public static VulnerabilityRequest vulnerabilityRequest(String ip, Long credentialId) {
        VulnerabilityRequest request = new VulnerabilityRequest();
        request.setIp(ip);
        request.setInfrastructureCredentialId(credentialId);
        return request;
    }

    public static String basicAuthHeader(String username, String password) {
        return "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
    }
}