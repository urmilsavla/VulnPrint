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

@RestController
@RequestMapping("/api/config")
public class ConfigRestController {

    @Autowired
    private SystemConfigRepository systemConfigRepository;

    @Autowired
    private SecurityUtils securityUtils;

    @GetMapping
    public ResponseEntity<?> getAllConfigs(@RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "MANAGE_MICROSERVICES")) {
            return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        }
        return ResponseEntity.ok(systemConfigRepository.findAll());
    }

    @GetMapping("/{key}")
    public ResponseEntity<?> getConfig(@PathVariable String key, @RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "MANAGE_MICROSERVICES")) {
            return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        }
        return ResponseEntity.ok(systemConfigRepository.findById(key).orElse(new SystemConfig(key, "")));
    }

    @PutMapping
    public ResponseEntity<?> saveConfig(@RequestBody SystemConfig config, @RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "MANAGE_MICROSERVICES")) {
            return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        }
        return ResponseEntity.ok(systemConfigRepository.save(config));
    }

    @GetMapping("/test-connection")
    public ResponseEntity<?> testConnection(@RequestParam String url, @RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "MANAGE_MICROSERVICES")) {
            return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        }
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
    public ResponseEntity<?> getRepGenUrl(@RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "GENERATE_REPORT")) {
            return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        }
        return ResponseEntity.ok(Map.of("url", systemConfigRepository.findById("repgen_url").map(SystemConfig::getConfigValue).orElse("")));
    }
}
