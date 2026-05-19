package com.devsecops.vulncheckerbackend.repositories;

import com.devsecops.vulncheckerbackend.entities.AgentEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface AgentRepository extends JpaRepository<AgentEntity, Long> {
    Optional<AgentEntity> findByWazuhAgentId(String wazuhAgentId);
}