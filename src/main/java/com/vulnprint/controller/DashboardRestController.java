package com.vulnprint.controller;

import com.vulnprint.model.Alert;
import com.vulnprint.model.Pentest;
import com.vulnprint.model.Vulnerability;
import com.vulnprint.model.User;
import com.vulnprint.repository.AlertRepository;
import com.vulnprint.repository.PentestRepository;
import com.vulnprint.repository.VulnerabilityRepository;
import com.vulnprint.security.AppSecurityGuard;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.*;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.ResponseEntity;
// Imports consolidated

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;

@RestController
@RequestMapping("/api/dashboard")
@Transactional(readOnly = true)
public class DashboardRestController {

    @Autowired
    private PentestRepository pentestRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private AlertRepository alertRepository;

    @Autowired
    private AppSecurityGuard guard;

    private List<Pentest> getAuthorizedPentests(User user) {
        if (guard.hasPermission(user, AppSecurityGuard.VIEW_ALL_PROJECTS)) {
            return pentestRepository.findAll();
        }
        if (guard.hasPermission(user, AppSecurityGuard.VIEW_ASSIGNED_PROJECTS)) {
            return pentestRepository.findByAssignedPentestersId(user.getId());
        }
        return new ArrayList<>();
    }

    @GetMapping("/metrics")
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).VIEW_DASHBOARD)")
    public ResponseEntity<?> getMetrics() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Map<String, Object> map = new HashMap<>();
        List<Pentest> authorized = getAuthorizedPentests(user);
        
        List<Vulnerability> allVulns = authorized.stream()
                .filter(p -> p.getVulnerabilities() != null)
                .flatMap(p -> p.getVulnerabilities().stream())
                .filter(v -> v != null)
                .collect(Collectors.toList());
        
        map.put("totalPentests", authorized.size());
        map.put("totalVulnerabilities", allVulns.size());
        
        long crit = allVulns.stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("CRITICAL")).count();
        long high = allVulns.stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("HIGH")).count();
        long med = allVulns.stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("MEDIUM")).count();
        long low = allVulns.stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("LOW")).count();
        long info = allVulns.stream().filter(v -> v.getSeverity() != null && (v.getSeverity().equalsIgnoreCase("INFO") || v.getSeverity().equalsIgnoreCase("INFORMATIONAL"))).count();
        
        map.put("critical", crit);
        map.put("high", high);
        map.put("medium", med);
        map.put("low", low);
        map.put("info", info);
        
        double weighted = (crit * 10) + (high * 7) + (med * 4) + (low * 2) + (info * 0.1);
        double score = allVulns.isEmpty() ? 0.0 : Math.min(10.0, weighted / allVulns.size());
        map.put("globalRiskScore", String.format("%.1f", score));
        
        return ResponseEntity.ok(map);
    }

    @GetMapping("/recent")
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).VIEW_DASHBOARD)")
    public ResponseEntity<?> getRecent() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        List<Pentest> authorized = getAuthorizedPentests(user);
        return ResponseEntity.ok(authorized.stream()
                .sorted((p1, p2) -> {
                    LocalDateTime d1 = p1.getCreatedDate() != null ? p1.getCreatedDate() : LocalDateTime.MIN;
                    LocalDateTime d2 = p2.getCreatedDate() != null ? p2.getCreatedDate() : LocalDateTime.MIN;
                    return d2.compareTo(d1);
                })
                .limit(3)
                .collect(Collectors.toList()));
    }

    @GetMapping("/vulnerabilities")
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).VIEW_ALL_VULNS) or hasAuthority(T(com.vulnprint.security.AppSecurityGuard).VIEW_ASSIGNED_VULNS)")
    public ResponseEntity<?> getRecentVulnerabilities() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        List<Pentest> authorized = getAuthorizedPentests(user);
        return ResponseEntity.ok(authorized.stream()
                .filter(p -> p.getVulnerabilities() != null)
                .flatMap(p -> p.getVulnerabilities().stream())
                .sorted((v1, v2) -> v2.getId().compareTo(v1.getId()))
                .limit(15)
                .map(v -> {
                    Map<String, Object> m = new HashMap<>();
                    m.put("id", v.getId());
                    m.put("title", v.getTitle());
                    m.put("severity", v.getSeverity());
                    m.put("cvssScore", v.getCvssScore());
                    m.put("status", v.getStatus());
                    m.put("pentestId", v.getPentest().getId());
                    m.put("pentestApp", v.getPentest().getApplicationName());
                    m.put("description", v.getDescription());
                    return m;
                }).collect(Collectors.toList()));
    }

    @GetMapping("/vulnerabilities/pending")
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).APPROVE_ALL_VULNS) or hasAuthority(T(com.vulnprint.security.AppSecurityGuard).APPROVE_ASSIGNED_VULNS)")
    public ResponseEntity<?> getPendingVulnerabilities() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        List<Vulnerability> pending;
        
        if (guard.hasPermission(user, AppSecurityGuard.APPROVE_ALL_VULNS)) {
            pending = vulnerabilityRepository.findByReportingStatusIgnoreCase("Sent for Approval");
        } else {
            // Only show pending findings for projects they are assigned to
            pending = vulnerabilityRepository.findByReportingStatusIgnoreCase("Sent for Approval").stream()
                    .filter(v -> v.getPentest() != null && v.getPentest().getAssignedPentesters().stream()
                            .anyMatch(u -> u.getId().equals(user.getId())))
                    .collect(Collectors.toList());
        }

        List<Map<String, Object>> mapped = pending.stream()
                .map(v -> {
                    Map<String, Object> m = new HashMap<>();
                    m.put("id", v.getId());
                    m.put("title", v.getTitle());
                    m.put("severity", v.getSeverity());
                    m.put("reportingStatus", v.getReportingStatus());
                    m.put("description", v.getDescription());
                    m.put("impact", v.getImpact());
                    m.put("mitigation", v.getMitigation());
                    m.put("cvssScore", v.getCvssScore());
                    m.put("cvssVector", v.getCvssVector());
                    m.put("cweReference", v.getCweReference());
                    m.put("owasp", v.getOwasp());
                    m.put("evidenceMode", v.getEvidenceMode());
                    m.put("steps", v.getSteps());
                    m.put("pocFolderPath", v.getPocFolderPath());
                    if (v.getPentest() != null) {
                        m.put("pentestId", v.getPentest().getId());
                        m.put("pentestName", v.getPentest().getPentestName());
                    }
                    return m;
                })
                .collect(Collectors.toList());
                
        return ResponseEntity.ok(mapped);
    }

    @GetMapping("/alerts")
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).VIEW_ALERTS)")
    public ResponseEntity<?> getAlerts() {
        return ResponseEntity.ok(alertRepository.findAll().stream()
                .filter(a -> !a.isRead())
                .sorted((a1, a2) -> a2.getId().compareTo(a1.getId()))
                .limit(10)
                .collect(Collectors.toList()));
    }

    @PostMapping("/alerts/{id}/read")
    @Transactional
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).MANAGE_ALERTS)")
    public ResponseEntity<?> markAlertRead(@PathVariable Long id) {
        return alertRepository.findById(id).map(a -> {
            a.setRead(true);
            alertRepository.save(a);
            return ResponseEntity.ok().build();
        }).orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/pentests")
    @PreAuthorize("hasAuthority(T(com.vulnprint.security.AppSecurityGuard).VIEW_DASHBOARD)")
    public ResponseEntity<?> getPentests(@RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "3") int size, @RequestParam(required = false) String type) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        List<Pentest> authorized = getAuthorizedPentests(user);
        
        // Apply category filter if needed
        List<Pentest> filtered;
        if (type != null && !type.isEmpty() && !type.equalsIgnoreCase("undefined") && !type.equalsIgnoreCase("All") && !type.equalsIgnoreCase("Total")) {
            filtered = authorized.stream().filter(p -> type.equalsIgnoreCase(p.getPentestType())).collect(Collectors.toList());
        } else {
            filtered = authorized;
        }

        // Apply manual pagination on the filtered list
        int start = Math.min(page * size, filtered.size());
        int end = Math.min(start + size, filtered.size());
        List<Pentest> paged = filtered.subList(start, end);

        return ResponseEntity.ok(paged.stream().map(p -> {
            Map<String, Object> map = new HashMap<>();
            map.put("id", p.getId());
            map.put("pentestName", p.getPentestName());
            map.put("applicationName", p.getApplicationName());
            map.put("clientName", p.getClientName());
            map.put("clientSpocName", p.getClientSpocName());
            map.put("clientSpocContact", p.getClientSpocContact());
            map.put("pentestType", p.getPentestType());
            map.put("target", p.getTarget());
            map.put("status", p.getStatus());
            map.put("assignedPentesters", p.getAssignedPentesters());
            
            // Safe Time ago calculation
            java.time.LocalDateTime lastDate = p.getLastModifiedDate();
            if (lastDate == null) lastDate = p.getCreatedDate();
            
            String timeAgo = "Just now";
            if (lastDate != null) {
                try {
                    long days = java.time.Duration.between(lastDate, java.time.LocalDateTime.now()).toDays();
                    timeAgo = days == 0 ? "Today" : days + "d ago";
                } catch (Exception e) {
                    timeAgo = "Recently";
                }
            }
            map.put("lastModifiedTimeAgo", timeAgo);
            
            // Vulnerability counts with null checks
            long crit = p.getVulnerabilities().stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("CRITICAL")).count();
            long high = p.getVulnerabilities().stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("HIGH")).count();
            long med = p.getVulnerabilities().stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("MEDIUM")).count();
            long low = p.getVulnerabilities().stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("LOW")).count();
            long info = p.getVulnerabilities().stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("INFORMATIONAL")).count();
            
            map.put("critical", crit);
            map.put("high", high);
            map.put("medium", med);
            map.put("low", low);
            map.put("info", info);
            
            double pWeighted = (crit * 10) + (high * 7) + (med * 4) + (low * 2) + (info * 0.1);
            double pScore = p.getVulnerabilities().isEmpty() ? 0.0 : Math.min(10.0, pWeighted / p.getVulnerabilities().size());
            map.put("riskIndex", String.format("%.1f", pScore));
            
            return map;
        }).collect(Collectors.toList()));
    }
}
