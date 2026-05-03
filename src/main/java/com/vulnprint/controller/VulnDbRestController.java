package com.vulnprint.controller;

import com.vulnprint.service.VulnDbService;
import com.vulnprint.repository.SystemConfigRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/vulndb")
public class VulnDbRestController {

    @Autowired
    private VulnDbService vulnDbService;

    @Autowired
    private SystemConfigRepository systemConfigRepository;

    private boolean isEnabled() {
        return systemConfigRepository.findById("vulndb_enabled")
                .map(c -> "true".equalsIgnoreCase(c.getConfigValue()))
                .orElse(false);
    }

    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam(required = false) String q,
                                     @RequestParam(required = false) String category,
                                     @RequestParam(required = false) String severity) {
        if (!isEnabled()) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("error", "VulnDB service is currently disabled in Microservice Management."));
        }
        return ResponseEntity.ok(vulnDbService.search(q, category, severity));
    }

    @GetMapping("/vulns/{slug}")
    public ResponseEntity<?> getVulnerability(@PathVariable String slug) {
        if (!isEnabled()) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("error", "VulnDB service is currently disabled."));
        }
        return ResponseEntity.ok(vulnDbService.getVulnerability(slug));
    }
}
