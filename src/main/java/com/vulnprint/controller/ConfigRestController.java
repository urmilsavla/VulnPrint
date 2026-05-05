package com.vulnprint.controller;

import com.vulnprint.model.SystemConfig;
import com.vulnprint.repository.SystemConfigRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

import com.vulnprint.model.User;
import com.vulnprint.service.SecurityUtils;

import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api/config")
public class ConfigRestController {

    @Autowired
    private SystemConfigRepository systemConfigRepository;

    @Autowired
    private SecurityUtils securityUtils;

    @GetMapping
    @PreAuthorize("hasAuthority('MANAGE_MICROSERVICES')")
    public ResponseEntity<?> getAllConfigs() {
        return ResponseEntity.ok(systemConfigRepository.findAll());
    }

    @GetMapping("/{key}")
    @PreAuthorize("hasAuthority('MANAGE_MICROSERVICES')")
    public ResponseEntity<?> getConfig(@PathVariable String key) {
        return ResponseEntity.ok(systemConfigRepository.findById(key).orElse(new SystemConfig(key, "")));
    }

    @GetMapping("/status")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getFeatureStatus() {
        Map<String, String> status = Map.of(
            "vulndb_enabled", systemConfigRepository.findById("vulndb_enabled").map(SystemConfig::getConfigValue).orElse("false"),
            "repgen_enabled", systemConfigRepository.findById("repgen_enabled").map(SystemConfig::getConfigValue).orElse("false")
        );
        return ResponseEntity.ok(status);
    }

    @PutMapping
    @PreAuthorize("hasAuthority('MANAGE_MICROSERVICES')")
    public ResponseEntity<?> saveConfig(@jakarta.validation.Valid @RequestBody com.vulnprint.dto.SystemConfigDTO dto) {
        SystemConfig config = new SystemConfig(dto.getConfigKey(), dto.getConfigValue());
        return ResponseEntity.ok(systemConfigRepository.save(config));
    }

    @GetMapping("/test-connection")
    @PreAuthorize("hasAuthority('MANAGE_MICROSERVICES')")
    public ResponseEntity<?> testConnection(@RequestParam String url) {
        try {
            org.springframework.web.client.RestClient.create()
                    .get()
                    .uri(url)
                    .retrieve()
                    .toBodilessEntity();
            return ResponseEntity.ok(Map.of("success", true));
        } catch (Exception e) {
            return ResponseEntity.ok(Map.of("success", false, "error", e.getMessage()));
        }
    }

    @GetMapping("/repgen-url")
    @PreAuthorize("hasAuthority('GENERATE_REPORT')")
    public ResponseEntity<?> getRepGenUrl() {
        return ResponseEntity.ok(Map.of("url", systemConfigRepository.findById("repgen_url").map(SystemConfig::getConfigValue).orElse("")));
    }
}
