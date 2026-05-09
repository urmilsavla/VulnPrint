package com.vulnprint.controller;

import com.vulnprint.model.SystemConfig;
import com.vulnprint.repository.SystemConfigRepository;
import com.vulnprint.security.AppSecurityGuard;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

import com.vulnprint.model.User;

import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api/config")
public class ConfigRestController {

    @Autowired
    private SystemConfigRepository systemConfigRepository;

    @Autowired
    private AppSecurityGuard guard;

    @GetMapping
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).MANAGE_MICROSERVICES)")
    public ResponseEntity<?> getAllConfigs() {
        return ResponseEntity.ok(systemConfigRepository.findAll());
    }

    @GetMapping("/{key}")
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).MANAGE_MICROSERVICES)")
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
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).MANAGE_MICROSERVICES)")
    public ResponseEntity<?> saveConfig(@jakarta.validation.Valid @RequestBody com.vulnprint.dto.SystemConfigDTO dto) {
        // Sanitize configuration values to prevent stored XSS
        SystemConfig config = new SystemConfig(guard.sanitize(dto.getConfigKey()), guard.sanitize(dto.getConfigValue()));
        return ResponseEntity.ok(systemConfigRepository.save(config));
    }

    @GetMapping("/test-connection")
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).MANAGE_MICROSERVICES)")
    public ResponseEntity<?> testConnection(@RequestParam String url) {
        // 1. SSRF Protection
        String safeUrl = guard.resolveSafeUrl(url);
        if (safeUrl == null) {
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "The provided configuration URL is restricted or unsafe."));
        }

        try {
            org.springframework.http.client.SimpleClientHttpRequestFactory factory = new org.springframework.http.client.SimpleClientHttpRequestFactory();
            factory.setConnectTimeout(5000);
            factory.setReadTimeout(5000);

            org.springframework.web.client.RestClient.builder()
                    .requestFactory(factory)
                    .defaultHeader("Host", new java.net.URL(url).getHost())
                    .build()
                    .get()
                    .uri(safeUrl)
                    .retrieve()
                    .toBodilessEntity();
            return ResponseEntity.ok(Map.of("success", true));
        } catch (Exception e) {
            return ResponseEntity.ok(Map.of("success", false, "message", "Connection test failed. Verify the service is reachable."));
        }
    }

    @GetMapping("/repgen-url")
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).GENERATE_REPORT)")
    public ResponseEntity<?> getRepGenUrl() {
        return ResponseEntity.ok(Map.of("url", systemConfigRepository.findById("repgen_url").map(SystemConfig::getConfigValue).orElse("")));
    }
}
