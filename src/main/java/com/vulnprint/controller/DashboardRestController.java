package com.vulnprint.controller;

import com.vulnprint.model.User;
import com.vulnprint.service.DashboardService;
import com.vulnprint.security.AppSecurityGuard;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

@RestController
@RequestMapping("/api/dashboard")
@Transactional(readOnly = true)
public class DashboardRestController {

    @Autowired
    private DashboardService dashboardService;

    @GetMapping("/metrics")
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).VIEW_DASHBOARD)")
    public ResponseEntity<?> getMetrics() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return ResponseEntity.ok(dashboardService.getMetrics(user));
    }

    @GetMapping("/recent")
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).VIEW_DASHBOARD)")
    public ResponseEntity<?> getRecent() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return ResponseEntity.ok(dashboardService.getRecent(user));
    }

    @GetMapping("/vulnerabilities")
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).VIEW_ALL_VULNS) or hasAuthority(T(com.vulnprint.security.AppSecurityGuard).VIEW_ASSIGNED_VULNS)")
    public ResponseEntity<?> getRecentVulnerabilities() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return ResponseEntity.ok(dashboardService.getRecentVulnerabilities(user));
    }

    @GetMapping("/vulnerabilities/pending")
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).APPROVE_ALL_VULNS) or hasAuthority(T(com.vulnprint.security.AppSecurityGuard).APPROVE_ASSIGNED_VULNS)")
    public ResponseEntity<?> getPendingVulnerabilities() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return ResponseEntity.ok(dashboardService.getPendingVulnerabilities(user));
    }

    @GetMapping("/alerts")
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).VIEW_ALERTS)")
    public ResponseEntity<?> getAlerts() {
        return ResponseEntity.ok(dashboardService.getAlerts());
    }

    @PostMapping("/alerts/{id}/read")
    @Transactional
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).MANAGE_ALERTS)")
    public ResponseEntity<?> markAlertRead(@PathVariable Long id) {
        boolean updated = dashboardService.markAlertRead(id);
        if (updated) {
            return ResponseEntity.ok().body(Map.of("message", "Alert status updated."));
        } else {
            return ResponseEntity.status(404).body(Map.of("message", "Alert not found."));
        }
    }

    @GetMapping("/pentests")
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).VIEW_DASHBOARD)")
    public ResponseEntity<?> getPentests(@RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "3") int size, @RequestParam(required = false) String type) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return ResponseEntity.ok(dashboardService.getPentests(user, page, size, type));
    }
}