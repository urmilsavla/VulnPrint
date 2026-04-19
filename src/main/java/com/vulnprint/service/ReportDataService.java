package com.vulnprint.service;

import com.vulnprint.model.*;
import com.vulnprint.repository.PentestRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Service responsible for consolidating all pentest and vulnerability data into a "Master Package".
 * 
 * IMPORTANT: This Master API is designed to feed a docx-template report generation system.
 * Any structural changes to the JSON output (Assessment Metadata, Report Configuration, 
 * Security Findings) must be coordinated with the placeholders defined in the .docx template.
 */
@Service
public class ReportDataService {

    @Autowired
    private PentestRepository pentestRepository;

    @Autowired
    private ResourceLoader resourceLoader;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * @deprecated Use {@link #getMasterReportDataV2(Long)} instead.
     * This version is inefficient as it embeds large Base64 images multiple times.
     */
    @Deprecated
    @Transactional(readOnly = true)
    public Map<String, Object> getMasterReportData(Long pentestId) {
        Pentest p = pentestRepository.findById(pentestId)
                .orElseThrow(() -> new RuntimeException("Assessment ID " + pentestId + " not found."));

        Map<String, Object> masterPackage = new LinkedHashMap<>();

        // SECTION 1: ASSESSMENT METADATA
        Map<String, Object> metadata = new LinkedHashMap<>();
        
        Map<String, Object> identity = new LinkedHashMap<>();
        identity.put("id", p.getId());
        identity.put("pentestName", p.getPentestName());
        identity.put("applicationName", p.getApplicationName());
        identity.put("pentestType", p.getPentestType());
        identity.put("status", p.getStatus());
        identity.put("createdDate", p.getCreatedDate());
        identity.put("lastModifiedDate", p.getLastModifiedDate());
        identity.put("globalRiskIndex", calculateRiskIndex(p.getVulnerabilities()));
        metadata.put("identity", identity);

        Map<String, Object> client = new LinkedHashMap<>();
        client.put("clientName", p.getClientName());
        client.put("clientSpocName", p.getClientSpocName());
        client.put("clientSpocContact", p.getClientSpocContact());
        metadata.put("client", client);

        Map<String, Object> scope = new LinkedHashMap<>();
        scope.put("target", p.getTarget());
        scope.put("url", p.getUrl());
        scope.put("osType", p.getOsType());
        scope.put("apiDomain", p.getApiDomain());
        scope.put("ipRanges", p.getIpRanges());
        scope.put("zipHash", p.getZipHash());
        scope.put("version", p.getVersion());
        scope.put("additionalUrls", p.getAdditionalUrls());
        scope.put("techStack", p.getTechStack());
        scope.put("packageName", p.getPackageName());
        scope.put("apiType", p.getApiType());
        scope.put("targetType", p.getTargetType());
        scope.put("repoUrl", p.getRepoUrl());
        scope.put("branchName", p.getBranchName());
        scope.put("language", p.getLanguage());
        metadata.put("technicalScope", scope);

        List<Map<String, Object>> auditors = new ArrayList<>();
        if (p.getAssignedPentesters() != null) {
            for (User u : p.getAssignedPentesters()) {
                Map<String, Object> auditor = new LinkedHashMap<>();
                auditor.put("id", u.getId());
                auditor.put("username", u.getUsername());
                auditor.put("fullName", u.getFirstName() + " " + u.getLastName());
                auditor.put("email", u.getEmail());
                auditor.put("role", u.getRole());
                auditor.put("address", u.getAddress());
                auditor.put("professionalQualifications", u.getQualification() != null ? u.getQualification() : "Certified Security Professional");
                auditor.put("profileImageBase64", u.getProfileImage()); 
                auditors.add(auditor);
            }
        }
        metadata.put("auditTeam", auditors);
        masterPackage.put("assessmentMetadata", metadata);

        // SECTION 2: REPORT CONFIGURATION
        Map<String, Object> config = new LinkedHashMap<>();
        
        config.put("disclaimer", Map.of(
            "isEnabled", p.getDisclaimerEnabled() != null ? p.getDisclaimerEnabled() : true,
            "text", p.getDisclaimer() != null ? p.getDisclaimer() : ""
        ));

        Map<String, Object> methodology = new LinkedHashMap<>();
        methodology.put("isEnabled", p.getMethodologyEnabled() != null ? p.getMethodologyEnabled() : true);
        methodology.put("displayMode", p.getMethodologyDisplayMode() != null ? p.getMethodologyDisplayMode() : "BOTH");
        methodology.put("text", p.getMethodology() != null ? p.getMethodology() : "");
        
        List<String> resolvedMethodImages = new ArrayList<>();
        if (p.getSelectedMethodologyImages() != null && !p.getSelectedMethodologyImages().isEmpty()) {
            for (String id : p.getSelectedMethodologyImages().split(",")) {
                if (id.startsWith("p_")) resolvedMethodImages.add(resolvePredefinedMethodologyImage(id));
                else if (id.startsWith("custom_")) {
                    try {
                        List<String> pool = objectMapper.readValue(p.getMethodologyImage(), List.class);
                        int idx = Integer.parseInt(id.replace("custom_", ""));
                        if (idx < pool.size()) resolvedMethodImages.add(pool.get(idx));
                    } catch (Exception ignored) {}
                }
            }
        }
        methodology.put("base64Images", resolvedMethodImages);
        config.put("assessmentMethodology", methodology);

        Map<String, Object> riskOverview = new LinkedHashMap<>();
        riskOverview.put("isEnabled", p.getRiskOverviewEnabled() != null ? p.getRiskOverviewEnabled() : true);
        riskOverview.put("summaryNote", p.getRiskSummary() != null ? p.getRiskSummary() : "");
        
        List<Vulnerability> vulns = p.getVulnerabilities() != null ? p.getVulnerabilities() : new ArrayList<>();
        Map<String, Long> counts = new HashMap<>();
        counts.put("CRITICAL", vulns.stream().filter(v -> "Critical".equalsIgnoreCase(v.getSeverity())).count());
        counts.put("HIGH", vulns.stream().filter(v -> "High".equalsIgnoreCase(v.getSeverity())).count());
        counts.put("MEDIUM", vulns.stream().filter(v -> "Medium".equalsIgnoreCase(v.getSeverity())).count());
        counts.put("LOW", vulns.stream().filter(v -> "Low".equalsIgnoreCase(v.getSeverity())).count());
        counts.put("INFORMATIONAL", vulns.stream().filter(v -> "Informational".equalsIgnoreCase(v.getSeverity()) || "Info".equalsIgnoreCase(v.getSeverity())).count());
        riskOverview.put("distributionMetrics", counts);
        config.put("riskOverview", riskOverview);

        Map<String, Object> frameworks = new LinkedHashMap<>();
        frameworks.put("isEnabled", p.getOwaspEnabled() != null ? p.getOwaspEnabled() : true);
        frameworks.put("activeFrameworks", p.getOwaspTop10() != null ? Arrays.asList(p.getOwaspTop10().split(",")) : new ArrayList<>());
        frameworks.put("detailedMapping", p.getSelectedOwaspCategories() != null ? Arrays.asList(p.getSelectedOwaspCategories().split("\\|\\|")) : new ArrayList<>());
        frameworks.put("owaspImageBase64", p.getOwaspImage());
        config.put("frameworkIntelligence", frameworks);

        Map<String, Object> severity = new LinkedHashMap<>();
        severity.put("isEnabled", p.getSeverityEnabled() != null ? p.getSeverityEnabled() : true);
        try {
            severity.put("definitions", p.getSeverityDefinitions() != null ? objectMapper.readValue(p.getSeverityDefinitions(), List.class) : new ArrayList<>());
        } catch (Exception e) { severity.put("definitions", new ArrayList<>()); }
        config.put("severityMatrix", severity);

        config.put("conclusion", Map.of(
            "isEnabled", p.getConclusionEnabled() != null ? p.getConclusionEnabled() : true,
            "text", p.getConclusion() != null ? p.getConclusion() : ""
        ));

        masterPackage.put("reportConfiguration", config);

        // SECTION 3: SECURITY FINDINGS
        List<Map<String, Object>> findings = new ArrayList<>();
        if (p.getVulnerabilities() != null) {
            for (Vulnerability v : p.getVulnerabilities()) {
                Map<String, Object> finding = new LinkedHashMap<>();
                finding.put("id", v.getId());
                finding.put("refId", "VULN-" + String.format("%03d", v.getId()));
                finding.put("title", v.getTitle());
                finding.put("severity", v.getSeverity());
                finding.put("cvssScore", v.getCvssScore());
                finding.put("cvssVector", v.getCvssVector());
                finding.put("owaspCategory", v.getOwasp());
                finding.put("cweReference", v.getCweReference());
                finding.put("description", v.getDescription());
                finding.put("impact", v.getImpact());
                finding.put("mitigation", v.getMitigation());
                finding.put("status", v.getStatus());
                finding.put("evidenceMode", v.getEvidenceMode());

                finding.put("requestResponse", v.getRequestResponse());
                finding.put("fileName", v.getFileName());
                finding.put("lineNumber", v.getLineNumber());
                finding.put("codeSnippetBase64", v.getCodeSnippet());

                List<Map<String, Object>> instances = new ArrayList<>();
                if (v.getSteps() != null) {
                    for (VulnerabilityStep s : v.getSteps()) {
                        Map<String, Object> instanceData = new LinkedHashMap<>();
                        instanceData.put("id", s.getId());
                        instanceData.put("sequence", s.getStepNumber());
                        instanceData.put("description", s.getDescription());
                        instanceData.put("request", s.getRequest());
                        instanceData.put("response", s.getResponse());
                        instanceData.put("fileName", s.getFileName());
                        instanceData.put("lineNumber", s.getLineNumber());
                        
                        List<String> evidenceBase64 = new ArrayList<>();
                        if (s.getImagePaths() != null) {
                            for (String img : s.getImagePaths()) {
                                String b64 = encodeFileToBase64(v.getPocFolderPath(), img);
                                if (b64 != null) evidenceBase64.add(b64);
                            }
                        }
                        instanceData.put("evidenceBase64", evidenceBase64);
                        instances.add(instanceData);
                    }
                }
                finding.put("evidenceInstances", instances);
                findings.add(finding);
            }
        }
        
        Map<String, Integer> sevMap = Map.of("CRITICAL", 0, "HIGH", 1, "MEDIUM", 2, "LOW", 3, "INFORMATIONAL", 4, "INFO", 4);
        findings.sort((a, b) -> {
            int aVal = sevMap.getOrDefault(a.get("severity").toString().toUpperCase(), 5);
            int bVal = sevMap.getOrDefault(b.get("severity").toString().toUpperCase(), 5);
            return Integer.compare(aVal, bVal);
        });

        masterPackage.put("securityFindings", findings);

        return masterPackage;
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getMasterReportDataV2(Long pentestId) {
        Pentest p = pentestRepository.findById(pentestId)
                .orElseThrow(() -> new RuntimeException("Assessment ID " + pentestId + " not found."));

        Map<String, Object> masterPackage = new LinkedHashMap<>();
        Map<String, String> imageLibrary = new LinkedHashMap<>();
        int imgCounter = 1;

        // Metadata
        Map<String, Object> metadata = new LinkedHashMap<>();
        Map<String, Object> identity = new LinkedHashMap<>();
        identity.put("id", p.getId());
        identity.put("pentestName", p.getPentestName());
        identity.put("applicationName", p.getApplicationName());
        identity.put("pentestType", p.getPentestType());
        identity.put("status", p.getStatus());
        metadata.put("identity", identity);

        Map<String, Object> scope = new LinkedHashMap<>();
        scope.put("target", p.getTarget());
        scope.put("url", p.getUrl());
        scope.put("osType", p.getOsType());
        scope.put("apiDomain", p.getApiDomain());
        scope.put("ipRanges", p.getIpRanges());
        scope.put("repoUrl", p.getRepoUrl());
        metadata.put("technicalScope", scope);

        List<Map<String, Object>> auditors = new ArrayList<>();
        if (p.getAssignedPentesters() != null) {
            for (User u : p.getAssignedPentesters()) {
                Map<String, Object> auditor = new LinkedHashMap<>();
                auditor.put("fullName", u.getFirstName() + " " + u.getLastName());
                auditor.put("qualifications", u.getQualification());
                if (u.getProfileImage() != null) {
                    String imgId = "AUDITOR_" + imgCounter++;
                    imageLibrary.put(imgId, u.getProfileImage());
                    auditor.put("profileImageId", imgId);
                }
                auditors.add(auditor);
            }
        }
        metadata.put("auditTeam", auditors);
        masterPackage.put("assessmentMetadata", metadata);

        // Config
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("disclaimer", p.getDisclaimer());
        
        Map<String, Object> methodology = new LinkedHashMap<>();
        methodology.put("text", p.getMethodology());
        List<String> methodImgIds = new ArrayList<>();
        if (p.getSelectedMethodologyImages() != null && !p.getSelectedMethodologyImages().isEmpty()) {
            for (String id : p.getSelectedMethodologyImages().split(",")) {
                String b64 = "";
                if (id.startsWith("p_")) b64 = resolvePredefinedMethodologyImage(id);
                else if (id.startsWith("custom_")) {
                    try {
                        List<String> pool = objectMapper.readValue(p.getMethodologyImage(), List.class);
                        int idx = Integer.parseInt(id.replace("custom_", ""));
                        if (idx < pool.size()) b64 = pool.get(idx);
                    } catch (Exception ignored) {}
                }
                if (!b64.isEmpty()) {
                    String imgId = "METHOD_" + imgCounter++;
                    imageLibrary.put(imgId, b64);
                    methodImgIds.add(imgId);
                }
            }
        }
        methodology.put("imageIds", methodImgIds);
        config.put("assessmentMethodology", methodology);
        config.put("conclusion", p.getConclusion());
        masterPackage.put("reportConfiguration", config);

        // Findings
        List<Map<String, Object>> findings = new ArrayList<>();
        if (p.getVulnerabilities() != null) {
            for (Vulnerability v : p.getVulnerabilities()) {
                Map<String, Object> finding = new LinkedHashMap<>();
                finding.put("title", v.getTitle());
                finding.put("severity", v.getSeverity());
                finding.put("description", v.getDescription());
                
                if (v.getCodeSnippet() != null && !v.getCodeSnippet().isEmpty()) {
                    String imgId = "SNIPPET_" + imgCounter++;
                    imageLibrary.put(imgId, v.getCodeSnippet());
                    finding.put("codeSnippetImageId", imgId);
                }

                List<Map<String, Object>> instances = new ArrayList<>();
                if (v.getSteps() != null) {
                    for (VulnerabilityStep s : v.getSteps()) {
                        Map<String, Object> inst = new LinkedHashMap<>();
                        inst.put("instruction", s.getDescription());
                        List<String> instImgIds = new ArrayList<>();
                        if (s.getImagePaths() != null) {
                            for (String img : s.getImagePaths()) {
                                String b64 = encodeFileToBase64(v.getPocFolderPath(), img);
                                if (b64 != null) {
                                    String imgId = "VULN_POC_" + imgCounter++;
                                    imageLibrary.put(imgId, b64);
                                    instImgIds.add(imgId);
                                }
                            }
                        }
                        inst.put("evidenceImageIds", instImgIds);
                        instances.add(inst);
                    }
                }
                finding.put("instances", instances);
                findings.add(finding);
            }
        }
        masterPackage.put("securityFindings", findings);

        // Finally add the Library
        masterPackage.put("imageLibrary", imageLibrary);

        return masterPackage;
    }

    private String calculateRiskIndex(List<Vulnerability> vulns) {
        if (vulns == null || vulns.isEmpty()) return "0.0";
        double weighted = 0;
        for (Vulnerability v : vulns) {
            String s = v.getSeverity() != null ? v.getSeverity().toUpperCase() : "LOW";
            if (s.equals("CRITICAL")) weighted += 10;
            else if (s.equals("HIGH")) weighted += 7;
            else if (s.equals("MEDIUM")) weighted += 4;
            else if (s.equals("LOW")) weighted += 2;
            else weighted += 0.1;
        }
        return String.format("%.1f", Math.min(10.0, weighted / vulns.size()));
    }

    private String encodeFileToBase64(String folderPath, String fileName) {
        if (folderPath == null || fileName == null) return null;
        try {
            Path path = Paths.get(folderPath, fileName);
            if (Files.exists(path)) {
                byte[] bytes = Files.readAllBytes(path);
                String mimeType = Files.probeContentType(path);
                return "data:" + (mimeType != null ? mimeType : "image/png") + ";base64," + Base64.getEncoder().encodeToString(bytes);
            }
        } catch (IOException ignored) {}
        return null;
    }

    private String resolvePredefinedMethodologyImage(String id) {
        Map<String, String> paths = Map.of(
            "p_web", "classpath:/static/images/Methodologies/Web.png",
            "p_mobile", "classpath:/static/images/Methodologies/Mobile.png",
            "p_api", "classpath:/static/images/Methodologies/API.png",
            "p_infra", "classpath:/static/images/Methodologies/Infra.png",
            "p_code", "classpath:/static/images/Methodologies/CodeReview4.png"
        );
        String path = paths.get(id);
        if (path == null) return null;
        try {
            Resource resource = resourceLoader.getResource(path);
            byte[] bytes = resource.getInputStream().readAllBytes();
            return "data:image/png;base64," + Base64.getEncoder().encodeToString(bytes);
        } catch (IOException e) { return null; }
    }
}
