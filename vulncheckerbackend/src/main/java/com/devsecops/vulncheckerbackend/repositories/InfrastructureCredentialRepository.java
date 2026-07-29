package com.devsecops.vulncheckerbackend.repositories;

import com.devsecops.vulncheckerbackend.entities.InfrastructureCredentialEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface InfrastructureCredentialRepository extends JpaRepository<InfrastructureCredentialEntity, Long> {
    List<InfrastructureCredentialEntity> findByUserId(Long userId);

    Optional<InfrastructureCredentialEntity> findFirstBySshUserAndSshPasswordAndWazuhUserAndWazuhPassword(
            String sshUser,
            String sshPassword,
            String wazuhUser,
            String wazuhPassword
    );
}