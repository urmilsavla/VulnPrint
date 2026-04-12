package com.vulnprint.controller;

import com.vulnprint.model.Alert;
import com.vulnprint.model.Pentest;
import com.vulnprint.model.Vulnerability;
import com.vulnprint.repository.AlertRepository;
import com.vulnprint.repository.PentestRepository;
import com.vulnprint.repository.VulnerabilityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.*;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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

    @GetMapping("/metrics")
    public Map<String, Object> getMetrics() {
        Map<String, Object> map = new HashMap<>();
        List<Pentest> all = pentestRepository.findAll();
        List<Vulnerability> allVulns = all.stream()
                .flatMap(p -> p.getVulnerabilities().stream())
                .collect(Collectors.toList());
        
        map.put("totalPentests", all.size());
        map.put("totalVulnerabilities", allVulns.size());
        
        long crit = allVulns.stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("CRITICAL")).count();
        long high = allVulns.stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("HIGH")).count();
        long med = allVulns.stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("MEDIUM")).count();
        long low = allVulns.stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("LOW")).count();
        long info = allVulns.stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("INFORMATIONAL")).count();
        
        map.put("critical", crit);
        map.put("high", high);
        map.put("medium", med);
        map.put("low", low);
        map.put("info", info);
        
        double weighted = (crit * 10) + (high * 7) + (med * 4) + (low * 2) + (info * 0.1);
        double score = allVulns.isEmpty() ? 0.0 : Math.min(10.0, weighted / allVulns.size());
        map.put("globalRiskScore", String.format("%.1f", score));
        
        return map;
    }

    @GetMapping("/recent")
    public List<Pentest> getRecent() {
        return pentestRepository.findTop3ByOrderByCreatedDateDesc();
    }

    @GetMapping("/vulnerabilities")
    public List<Map<String, Object>> getRecentVulnerabilities() {
        return vulnerabilityRepository.findAll().stream()
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
                }).collect(Collectors.toList());
    }

    @GetMapping("/alerts")
    public List<Alert> getAlerts() {
        return alertRepository.findAll().stream()
                .sorted((a1, a2) -> a2.getId().compareTo(a1.getId()))
                .limit(5)
                .collect(Collectors.toList());
    }

    @GetMapping("/pentests")
    public List<Map<String, Object>> getPentests(@RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "3") int size, @RequestParam(required = false) String type) {
        Pageable pageable = PageRequest.of(page, size);
        Page<Pentest> pentestPage;
        
        if (type != null && !type.isEmpty() && !type.equalsIgnoreCase("undefined") && !type.equalsIgnoreCase("All") && !type.equalsIgnoreCase("Total")) {
            pentestPage = pentestRepository.findByPentestType(type, pageable);
        } else {
            pentestPage = pentestRepository.findAll(pageable);
        }

        return pentestPage.getContent().stream().map(p -> {
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
        }).collect(Collectors.toList());
    }
}
