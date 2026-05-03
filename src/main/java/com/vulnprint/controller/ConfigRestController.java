package com.vulnprint.controller;

import com.vulnprint.model.SystemConfig;
import com.vulnprint.repository.SystemConfigRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/config")
public class ConfigRestController {

    @Autowired
    private SystemConfigRepository systemConfigRepository;

    @GetMapping
    public List<SystemConfig> getAllConfigs() {
        return systemConfigRepository.findAll();
    }

    @GetMapping("/{key}")
    public SystemConfig getConfig(@PathVariable String key) {
        return systemConfigRepository.findById(key).orElse(new SystemConfig(key, ""));
    }

    @PutMapping
    public SystemConfig saveConfig(@RequestBody SystemConfig config) {
        return systemConfigRepository.save(config);
    }

    @GetMapping("/test-connection")
    public java.util.Map<String, Object> testConnection(@RequestParam String url) {
        try {
            org.springframework.web.client.RestClient.create()
                    .get()
                    .uri(url)
                    .retrieve()
                    .toBodilessEntity();
            return java.util.Map.of("success", true);
        } catch (Exception e) {
            return java.util.Map.of("success", false, "error", e.getMessage());
        }
    }
}
