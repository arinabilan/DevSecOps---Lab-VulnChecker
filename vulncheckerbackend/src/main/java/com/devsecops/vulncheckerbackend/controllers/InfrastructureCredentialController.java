package com.devsecops.vulncheckerbackend.controllers;

import com.devsecops.vulncheckerbackend.dto.InfraCredentialRequest;
import com.devsecops.vulncheckerbackend.entities.InfrastructureCredentialEntity;
import com.devsecops.vulncheckerbackend.services.InfrastructureCredentialService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/infra-credentials")
public class InfrastructureCredentialController {

    private final InfrastructureCredentialService service;

    public InfrastructureCredentialController(InfrastructureCredentialService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<InfrastructureCredentialEntity> create(@RequestBody InfraCredentialRequest request) {
        InfrastructureCredentialEntity credential = new InfrastructureCredentialEntity();
        credential.setUserId(request.getUserId());
        credential.setName(request.getName());
        credential.setSshUser(request.getSshUser());
        credential.setSshPassword(request.getSshPassword());
        credential.setWazuhUser(request.getWazuhUser());
        credential.setWazuhPassword(request.getWazuhPassword());
        return ResponseEntity.ok(service.save(credential));
    }

    @PutMapping("/{id}")
    public ResponseEntity<InfrastructureCredentialEntity> update(
            @PathVariable Long id, 
            @RequestBody InfraCredentialRequest request) {
        
        return service.findById(id)
                .map(existingCredential -> {
                    existingCredential.setName(request.getName());
                    existingCredential.setSshUser(request.getSshUser());
                    if (request.getSshPassword() != null && !request.getSshPassword().isEmpty()) {
                        existingCredential.setSshPassword(request.getSshPassword());
                    }
                    existingCredential.setWazuhUser(request.getWazuhUser());
                    if (request.getWazuhPassword() != null && !request.getWazuhPassword().isEmpty()) {
                        existingCredential.setWazuhPassword(request.getWazuhPassword());
                    }
                    
                    return ResponseEntity.ok(service.save(existingCredential));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/user/{userId}")
    public ResponseEntity<List<InfrastructureCredentialEntity>> getByUser(@PathVariable Long userId) {
        return ResponseEntity.ok(service.getByUserId(userId));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        service.delete(id);
        return ResponseEntity.noContent().build();
    }
}