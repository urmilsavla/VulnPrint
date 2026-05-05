package com.vulnprint.controller;

import com.vulnprint.service.ReportDataService;
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
@RequestMapping("/api")
public class RepGenRestController {

    @Autowired
    private ReportDataService reportDataService;

    @Autowired
    private SystemConfigRepository systemConfigRepository;

    @Autowired
    private AppSecurityGuard guard;

    private boolean isEnabled() {
        return systemConfigRepository.findById("repgen_enabled")
                .map(c -> "true".equalsIgnoreCase(c.getConfigValue()))
                .orElse(false);
    }

    @GetMapping("/repGenApi/{pentestId}")
    @PreAuthorize("hasAuthority('GENERATE_REPORT') and @securityService.canViewProject(#pentestId)")
    public ResponseEntity<?> getReportGenerationData(@PathVariable Long pentestId) {
        if (!isEnabled()) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("error", "Microservice disabled by Admin."));
        }
        try {
            Map<String, Object> data = reportDataService.getReportGenerationData(pentestId);
            return ResponseEntity.ok()
                    .header("Cache-Control", "no-cache, no-store, must-revalidate")
                    .header("Pragma", "no-cache")
                    .header("Expires", "0")
                    .body(data);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Internal Server Error: " + e.getMessage()));
        }
    }
}
