package com.vulnprint.service;

import com.vulnprint.model.Alert;
import com.vulnprint.model.Pentest;
import com.vulnprint.model.Vulnerability;
import com.vulnprint.model.User;
import com.vulnprint.repository.AlertRepository;
import com.vulnprint.repository.PentestRepository;
import com.vulnprint.repository.VulnerabilityRepository;
import com.vulnprint.security.AppSecurityGuard;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@Transactional(readOnly = true)
public class DashboardService {

    @Autowired
    private PentestRepository pentestRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private AlertRepository alertRepository;

    @Autowired
    private AppSecurityGuard guard;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.analytics.risk-weight.critical:10.0}")
    private double weightCritical;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.analytics.risk-weight.high:7.0}")
    private double weightHigh;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.analytics.risk-weight.medium:4.0}")
    private double weightMedium;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.analytics.risk-weight.low:2.0}")
    private double weightLow;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.analytics.risk-weight.info:0.1}")
    private double weightInfo;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.ui.dashboard.recent-activity-limit:15}")
    private int recentActivityLimit;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.ui.dashboard.recent-projects-limit:3}")
    private int recentProjectsLimit;

    private List<Pentest> getAuthorizedPentests(User user) {
        if (guard.hasPermission(user, AppSecurityGuard.VIEW_ALL_PROJECTS)) {
            return pentestRepository.findAll();
        }
        if (guard.hasPermission(user, AppSecurityGuard.VIEW_ASSIGNED_PROJECTS)) {
            return pentestRepository.findByAssignedPentestersId(user.getId());
        }
        return new ArrayList<>();
    }

    public Map<String, Object> getMetrics(User user) {
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
        
        double weighted = (crit * weightCritical) + (high * weightHigh) + (med * weightMedium) + (low * weightLow) + (info * weightInfo);
        double score = allVulns.isEmpty() ? 0.0 : Math.min(10.0, weighted / allVulns.size());
        map.put("globalRiskScore", String.format("%.1f", score));
        
        return map;
    }

    public List<Pentest> getRecent(User user) {
        List<Pentest> authorized = getAuthorizedPentests(user);
        return authorized.stream()
                .sorted((p1, p2) -> {
                    LocalDateTime d1 = p1.getCreatedDate() != null ? p1.getCreatedDate() : LocalDateTime.MIN;
                    LocalDateTime d2 = p2.getCreatedDate() != null ? p2.getCreatedDate() : LocalDateTime.MIN;
                    return d2.compareTo(d1);
                })
                .limit(recentProjectsLimit)
                .collect(Collectors.toList());
    }

    public List<Map<String, Object>> getRecentVulnerabilities(User user) {
        List<Pentest> authorized = getAuthorizedPentests(user);
        return authorized.stream()
                .filter(p -> p.getVulnerabilities() != null)
                .flatMap(p -> p.getVulnerabilities().stream())
                .sorted((v1, v2) -> v2.getId().compareTo(v1.getId()))
                .limit(recentActivityLimit)
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

    public List<Map<String, Object>> getPendingVulnerabilities(User user) {
        List<Vulnerability> pending;
        
        if (guard.hasPermission(user, AppSecurityGuard.APPROVE_ALL_VULNS)) {
            pending = vulnerabilityRepository.findByReportingStatusIgnoreCase("Sent for Approval");
        } else {
            pending = vulnerabilityRepository.findByReportingStatusIgnoreCase("Sent for Approval").stream()
                    .filter(v -> v.getPentest() != null && v.getPentest().getAssignedPentesters().stream()
                            .anyMatch(u -> u.getId().equals(user.getId())))
                    .collect(Collectors.toList());
        }

        return pending.stream()
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
    }

    public List<Alert> getAlerts() {
        return alertRepository.findAll().stream()
                .filter(a -> !a.isRead())
                .sorted((a1, a2) -> a2.getId().compareTo(a1.getId()))
                .limit(10)
                .collect(Collectors.toList());
    }

    @Transactional
    public boolean markAlertRead(Long id) {
        return alertRepository.findById(id).map(a -> {
            a.setRead(true);
            alertRepository.save(a);
            return true;
        }).orElse(false);
    }

    public List<Map<String, Object>> getPentests(User user, int page, int size, String type) {
        List<Pentest> authorized = getAuthorizedPentests(user);
        
        List<Pentest> filtered;
        if (type != null && !type.isEmpty() && !type.equalsIgnoreCase("undefined") && !type.equalsIgnoreCase("All") && !type.equalsIgnoreCase("Total")) {
            filtered = authorized.stream().filter(p -> type.equalsIgnoreCase(p.getPentestType())).collect(Collectors.toList());
        } else {
            filtered = new ArrayList<>(authorized);
        }

        filtered.sort((p1, p2) -> {
            LocalDateTime d1 = p1.getCreatedDate() != null ? p1.getCreatedDate() : LocalDateTime.MIN;
            LocalDateTime d2 = p2.getCreatedDate() != null ? p2.getCreatedDate() : LocalDateTime.MIN;
            return d2.compareTo(d1);
        });

        int start = Math.min(page * size, filtered.size());
        int end = Math.min(start + size, filtered.size());
        List<Pentest> paged = filtered.subList(start, end);

        return paged.stream().map(p -> {
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
            
            long crit = p.getVulnerabilities().stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("CRITICAL")).count();
            long high = p.getVulnerabilities().stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("HIGH")).count();
            long med = p.getVulnerabilities().stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("MEDIUM")).count();
            long low = p.getVulnerabilities().stream().filter(v -> v.getSeverity() != null && v.getSeverity().equalsIgnoreCase("LOW")).count();
            long info = p.getVulnerabilities().stream().filter(v -> v.getSeverity() != null && (v.getSeverity().equalsIgnoreCase("INFO") || v.getSeverity().equalsIgnoreCase("INFORMATIONAL"))).count();
            
            map.put("critical", crit);
            map.put("high", high);
            map.put("medium", med);
            map.put("low", low);
            map.put("info", info);
            
            double pWeighted = (crit * weightCritical) + (high * weightHigh) + (med * weightMedium) + (low * weightLow) + (info * weightInfo);
            double pScore = p.getVulnerabilities().isEmpty() ? 0.0 : Math.min(10.0, pWeighted / p.getVulnerabilities().size());
            map.put("riskIndex", String.format("%.1f", pScore));
            
            return map;
        }).collect(Collectors.toList());
    }
}