package com.vulnprint.controller;

import com.vulnprint.service.VulnDbService;
import com.vulnprint.repository.SystemConfigRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

import com.vulnprint.model.User;
import com.vulnprint.security.AppSecurityGuard;

import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api/vulndb")
public class VulnDbRestController {

    @Autowired
    private VulnDbService vulnDbService;

    @Autowired
    private SystemConfigRepository systemConfigRepository;

    @Autowired
    private AppSecurityGuard guard;

    private boolean isEnabled() {
        return systemConfigRepository.findById("vulndb_url")
                .map(c -> !c.getConfigValue().isBlank())
                .orElse(false);
    }

    @GetMapping("/search")
    @PreAuthorize("hasAuthority('MANAGE_MICROSERVICES')")
    public ResponseEntity<?> search(@RequestParam(required = false) String q,
                                     @RequestParam(required = false) String category,
                                     @RequestParam(required = false) String severity) {
        if (!isEnabled()) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("message", "Vulnerability Database service is currently disabled in Microservice Management."));
        }
        return ResponseEntity.ok(vulnDbService.search(q, category, severity));
    }

    @GetMapping("/vulns/{slug}")
    @PreAuthorize("hasAuthority('MANAGE_MICROSERVICES')")
    public ResponseEntity<?> getVulnerability(@PathVariable String slug) {
        if (!isEnabled()) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("message", "Vulnerability Database service is currently disabled."));
        }
        return ResponseEntity.ok(vulnDbService.getVulnerability(slug));
    }
}
