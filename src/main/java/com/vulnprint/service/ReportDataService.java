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

@Service
public class ReportDataService {

    @Autowired
    private PentestRepository pentestRepository;

    @Autowired
    private ResourceLoader resourceLoader;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Transactional(readOnly = true)
    public Map<String, Object> getMasterReportData(Long pentestId) {
        Pentest p = pentestRepository.findById(pentestId)
                .orElseThrow(() -> new RuntimeException("Assessment ID " + pentestId + " not found."));

        Map<String, Object> masterPackage = new LinkedHashMap<>();

        // SECTION 1: ASSESSMENT METADATA
        Map<String, Object> metadata = new LinkedHashMap<>();
        
        Map<String, Object> identity = new LinkedHashMap<>();
        identity.put("assessmentId", p.getId());
        identity.put("assessmentName", p.getPentestName());
        identity.put("applicationName", p.getApplicationName());
        identity.put("assessmentType", p.getPentestType());
        identity.put("status", p.getStatus());
        identity.put("createdDate", p.getCreatedDate());
        identity.put("lastModifiedDate", p.getLastModifiedDate());
        metadata.put("projectIdentity", identity);

        Map<String, Object> client = new LinkedHashMap<>();
        client.put("organizationName", p.getClientName());
        client.put("primaryContactPerson", p.getClientSpocName());
        client.put("contactInformation", p.getClientSpocContact());
        metadata.put("clientContext", client);

        Map<String, Object> scope = new LinkedHashMap<>();
        scope.put("mainTarget", p.getTarget());
        scope.put("targetUrl", p.getUrl());
        scope.put("operatingSystem", p.getOsType());
        scope.put("apiEndpoint", p.getApiDomain());
        scope.put("networkIpRanges", p.getIpRanges());
        scope.put("sourceCodeHash", p.getZipHash());
        scope.put("softwareVersion", p.getVersion());
        scope.put("technologyStack", p.getTechStack());
        scope.put("packageName", p.getPackageName());
        scope.put("apiType", p.getApiType());
        scope.put("repoUrl", p.getRepoUrl());
        scope.put("branchName", p.getBranchName());
        scope.put("programmingLanguage", p.getLanguage());
        metadata.put("technicalScope", scope);

        List<Map<String, Object>> auditors = new ArrayList<>();
        if (p.getAssignedPentesters() != null) {
            for (User u : p.getAssignedPentesters()) {
                Map<String, Object> auditor = new LinkedHashMap<>();
                auditor.put("fullName", u.getFirstName() + " " + u.getLastName());
                auditor.put("professionalQualifications", u.getQualification() != null ? u.getQualification() : "Certified Security Professional");
                auditors.add(auditor);
            }
        }
        metadata.put("auditTeam", auditors);
        masterPackage.put("assessmentMetadata", metadata);

        // SECTION 2: SECURITY FINDINGS
        List<Map<String, Object>> findings = new ArrayList<>();
        if (p.getVulnerabilities() != null) {
            for (Vulnerability v : p.getVulnerabilities()) {
                Map<String, Object> finding = new LinkedHashMap<>();
                finding.put("vulnerabilityId", "VULN-" + String.format("%03d", v.getId()));
                finding.put("title", v.getTitle());
                finding.put("severity", v.getSeverity());
                finding.put("cvssScore", v.getCvssScore());
                finding.put("cvssVector", v.getCvssVector());
                finding.put("owaspCategory", v.getOwasp());
                finding.put("cweReference", v.getCweReference());
                finding.put("description", v.getDescription());
                finding.put("riskImpact", v.getImpact());
                finding.put("remediationGuidance", v.getMitigation());
                finding.put("status", v.getStatus());

                List<Map<String, Object>> steps = new ArrayList<>();
                if (v.getSteps() != null) {
                    for (VulnerabilityStep step : v.getSteps()) {
                        Map<String, Object> stepData = new LinkedHashMap<>();
                        stepData.put("sequence", step.getStepNumber());
                        stepData.put("instruction", step.getDescription());
                        
                        List<String> evidenceBase64 = new ArrayList<>();
                        if (step.getImagePaths() != null) {
                            for (String fileName : step.getImagePaths()) {
                                String b64 = encodeFileToBase64(v.getPocFolderPath(), fileName);
                                if (b64 != null) evidenceBase64.add(b64);
                            }
                        }
                        stepData.put("evidence", evidenceBase64);
                        steps.add(stepData);
                    }
                }
                finding.put("reproductionSteps", steps);
                findings.add(finding);
            }
        }
        masterPackage.put("securityFindings", findings);

        // SECTION 3: REPORT CONFIGURATION
        Map<String, Object> config = new LinkedHashMap<>();
        
        config.put("disclaimer", Map.of(
            "isEnabled", p.getDisclaimerEnabled() != null ? p.getDisclaimerEnabled() : true,
            "text", p.getDisclaimer() != null ? p.getDisclaimer() : ""
        ));

        Map<String, Object> methodology = new LinkedHashMap<>();
        methodology.put("isEnabled", p.getMethodologyEnabled() != null ? p.getMethodologyEnabled() : true);
        methodology.put("displayMode", p.getMethodologyDisplayMode() != null ? p.getMethodologyDisplayMode() : "BOTH");
        methodology.put("technicalDescription", p.getMethodology() != null ? p.getMethodology() : "");
        
        // Resolve Methodology Images (Predefined + Custom)
        List<String> resolvedImages = new ArrayList<>();
        if (p.getSelectedMethodologyImages() != null && !p.getSelectedMethodologyImages().isEmpty()) {
            String[] selectedIds = p.getSelectedMethodologyImages().split(",");
            for (String id : selectedIds) {
                if (id.startsWith("p_")) { // Predefined
                    resolvedImages.add(resolvePredefinedMethodologyImage(id));
                } else if (id.startsWith("custom_")) { // Custom
                    try {
                        List<String> pool = objectMapper.readValue(p.getMethodologyImage(), List.class);
                        int idx = Integer.parseInt(id.replace("custom_", ""));
                        if (idx < pool.size()) resolvedImages.add(pool.get(idx));
                    } catch (Exception ignored) {}
                }
            }
        }
        methodology.put("visualFrameworks", resolvedImages);
        config.put("assessmentMethodology", methodology);

        Map<String, Object> frameworks = new LinkedHashMap<>();
        frameworks.put("isEnabled", p.getOwaspEnabled() != null ? p.getOwaspEnabled() : true);
        frameworks.put("activeFrameworks", p.getOwaspTop10() != null ? Arrays.asList(p.getOwaspTop10().split(",")) : new ArrayList<>());
        frameworks.put("detailedFindingsMapping", p.getSelectedOwaspCategories() != null ? Arrays.asList(p.getSelectedOwaspCategories().split("\\|\\|")) : new ArrayList<>());
        config.put("frameworkIntelligence", frameworks);

        Map<String, Object> severity = new LinkedHashMap<>();
        severity.put("isEnabled", p.getSeverityEnabled() != null ? p.getSeverityEnabled() : true);
        try {
            severity.put("definitions", p.getSeverityDefinitions() != null ? objectMapper.readValue(p.getSeverityDefinitions(), List.class) : new ArrayList<>());
        } catch (Exception e) {
            severity.put("definitions", new ArrayList<>());
        }
        config.put("severityMatrix", severity);

        config.put("executiveSummary", Map.of(
            "isEnabled", p.getConclusionEnabled() != null ? p.getConclusionEnabled() : true,
            "text", p.getConclusion() != null ? p.getConclusion() : ""
        ));

        masterPackage.put("reportConfiguration", config);

        return masterPackage;
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
        } catch (IOException e) {
            return null;
        }
    }
}
