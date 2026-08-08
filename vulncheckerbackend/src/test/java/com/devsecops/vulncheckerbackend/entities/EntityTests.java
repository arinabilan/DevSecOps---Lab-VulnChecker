package com.devsecops.vulncheckerbackend.entities;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.*;

class EntityTests {

    @Test
    void vulnerabilityTimelineId_equalsAndHashCode() {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        VulnerabilityTimelineId id1 = new VulnerabilityTimelineId(now, 1L, "CVE-1", "pkg");
        VulnerabilityTimelineId id2 = new VulnerabilityTimelineId(now, 1L, "CVE-1", "pkg");
        VulnerabilityTimelineId id3 = new VulnerabilityTimelineId(now, 2L, "CVE-2", "pkg2");

        assertEquals(id1, id1);
        assertEquals(id1, id2);
        assertEquals(id1.hashCode(), id2.hashCode());
        assertNotEquals(id1, id3);
        assertNotEquals(id1, null);
        assertNotEquals(id1, "string");
        assertEquals(now, id1.getTime());
        assertEquals(1L, id1.getInfrastructureCredentialsId());
        assertEquals("CVE-1", id1.getCve());
        assertEquals("pkg", id1.getPackageName());
    }

    @Test
    void vulnerabilityTimelineId_noArgsConstructor() {
        VulnerabilityTimelineId id = new VulnerabilityTimelineId();
        assertNull(id.getTime());
        assertNull(id.getInfrastructureCredentialsId());
        assertNull(id.getCve());
        assertNull(id.getPackageName());
    }

    @Test
    void userEntity_setsAndGetsAllFields() {
        UserEntity entity = new UserEntity();
        entity.setId(1L);
        entity.setFirstName("John");
        entity.setPaternalLastName("Doe");
        entity.setMaternalLastName("Smith");
        entity.setEmail("john@test.com");
        entity.setPassword("secret");
        entity.setRole("ADMIN");
        entity.setActive(true);

        assertEquals(1L, entity.getId());
        assertEquals("John", entity.getFirstName());
        assertEquals("Doe", entity.getPaternalLastName());
        assertEquals("Smith", entity.getMaternalLastName());
        assertEquals("john@test.com", entity.getEmail());
        assertEquals("secret", entity.getPassword());
        assertEquals("ADMIN", entity.getRole());
        assertTrue(entity.isActive());
    }

    @Test
    void userEntity_setActiveNoArg() {
        UserEntity entity = new UserEntity();
        assertFalse(entity.isActive());
        entity.setActive();
        assertTrue(entity.isActive());
    }

    @Test
    void userEntity_prePersistSetsCreatedAt() {
        UserEntity entity = new UserEntity();
        assertNull(entity.getCreatedAt());
        entity.onCreate();
        assertNotNull(entity.getCreatedAt());
    }

    @Test
    void userEntity_setCreatedAt() {
        UserEntity entity = new UserEntity();
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        entity.setCreatedAt(now);
        assertEquals(now, entity.getCreatedAt());
    }

    @Test
    void vulnerabilitySnapshotEntity_setsAndGetsAllFields() {
        VulnerabilitySnapshotEntity entity = new VulnerabilitySnapshotEntity();
        entity.setId(1L);
        entity.setAgentId(1L);
        entity.setCriticalCount(10);
        entity.setHighCount(20);
        entity.setMediumCount(30);
        entity.setLowCount(40);
        entity.setTotalCount(100);
        LocalDateTime date = LocalDateTime.now(ZoneOffset.UTC);
        entity.setSnapshotDate(date);

        assertEquals(1L, entity.getId());
        assertEquals(1L, entity.getAgentId());
        assertEquals(10, entity.getCriticalCount());
        assertEquals(20, entity.getHighCount());
        assertEquals(30, entity.getMediumCount());
        assertEquals(40, entity.getLowCount());
        assertEquals(100, entity.getTotalCount());
        assertEquals(date, entity.getSnapshotDate());
    }

    @Test
    void vulnerabilitySnapshotEntity_prePersistSetsSnapshotDate() {
        VulnerabilitySnapshotEntity entity = new VulnerabilitySnapshotEntity();
        assertNull(entity.getSnapshotDate());
        entity.onCreate();
        assertNotNull(entity.getSnapshotDate());
    }

    @Test
    void credentialEntity_setsAndGetsAllFields() {
        CredentialEntity entity = new CredentialEntity();
        entity.setId(1L);
        entity.setCreatedByUserId(1L);
        entity.setUsernameCredentials("admin");
        entity.setPasswordCredentials("pass");

        assertEquals(1L, entity.getId());
        assertEquals(1L, entity.getCreatedByUserId());
        assertEquals("admin", entity.getUsernameCredentials());
        assertEquals("pass", entity.getPasswordCredentials());
    }

    @Test
    void reportSignatureEntity_setsAndGetsId() {
        ReportSignatureEntity entity = new ReportSignatureEntity();
        entity.setId(1L);
        assertEquals(1L, entity.getId());
    }

    @Test
    void credentialEntity_prePersistSetsCreatedAt() {
        CredentialEntity entity = new CredentialEntity();
        assertNull(entity.getCreatedAt());
        entity.onCreate();
        assertNotNull(entity.getCreatedAt());
    }
}
