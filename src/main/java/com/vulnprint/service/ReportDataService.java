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
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Service responsible for consolidating all pentest and vulnerability data into a structured Master Package for reporting.
 * Follows the strict 10-Section Architectural Requirement.
 */
@Service
public class ReportDataService {

    @Autowired
    private PentestRepository pentestRepository;

    @Autowired
    private ResourceLoader resourceLoader;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Transactional(readOnly = true)
    public Map<String, Object> getMasterReportDataV2(Long pentestId) {
        Pentest p = pentestRepository.findById(pentestId)
                .orElseThrow(() -> new RuntimeException("Assessment ID " + pentestId + " not found."));

        Map<String, Object> masterPackage = new LinkedHashMap<>();
        Map<String, String> imageLibrary = new LinkedHashMap<>();
        int imgCounter = 1;

        // --- SECTION 1: BASIC DETAILED ---
        Map<String, Object> section1 = new LinkedHashMap<>();
        String projectName = (p.getPentestName() != null && !p.getPentestName().isEmpty()) ? p.getPentestName() : p.getApplicationName();
        section1.put("projectName", projectName != null ? projectName : "N/A");
        section1.put("pentestType", p.getPentestType() != null ? p.getPentestType() : "N/A");
        section1.put("currentDateTime", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        masterPackage.put("section1", section1);

        // --- SECTION 2: DISCLAIMER ---
        Map<String, Object> section2 = new LinkedHashMap<>();
        section2.put("disclaimer", p.getDisclaimer() != null ? p.getDisclaimer() : "");
        masterPackage.put("section2", section2);

        // --- SECTION 3: CLIENT DETAILS ---
        Map<String, Object> section3 = new LinkedHashMap<>();
        section3.put("clientOrgName", p.getClientName() != null ? p.getClientName() : "N/A");
        section3.put("clientSpocName", p.getClientSpocName() != null ? p.getClientSpocName() : "N/A");
        section3.put("clientSpocContact", p.getClientSpocContact() != null ? p.getClientSpocContact() : "N/A");
        if (hasValue(p.getClientLogo())) {
            String imgId = "LOGO_CLIENT";
            imageLibrary.put(imgId, p.getClientLogo());
            section3.put("clientLogoId", imgId);
        }
        masterPackage.put("section3", section3);

        // --- SECTION 4: PROJECT DETAILS ---
        Map<String, Object> section4 = new LinkedHashMap<>();
        section4.put("projectName", projectName != null ? projectName : "N/A");
        section4.put("pentestType", p.getPentestType() != null ? p.getPentestType() : "N/A");
        section4.put("projectInitiationDate", p.getCreatedDate() != null ? p.getCreatedDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd")) : "N/A");
        
        String riskIndexValue = calculateRiskIndex(p.getVulnerabilities());
        section4.put("technicalScore", riskIndexValue); 
        section4.put("overallPentestRiskIndex", riskIndexValue);
        
        // Deep Factor Addition: Technical Scope items included in Project Details for completeness
        List<Map<String, String>> scopeItems = new ArrayList<>();
        if (hasValue(p.getTarget())) scopeItems.add(Map.of("label", "Scope Target", "value", p.getTarget()));
        if (hasValue(p.getUrl())) scopeItems.add(Map.of("label", "URL", "value", p.getUrl()));
        if (hasValue(p.getTechStack())) scopeItems.add(Map.of("label", "Tech Stack", "value", p.getTechStack()));
        if (hasValue(p.getIpRanges())) scopeItems.add(Map.of("label", "IP Ranges", "value", p.getIpRanges()));
        section4.put("scopeItems", scopeItems);
        masterPackage.put("section4", section4);

        // --- SECTION 5: TESTERS DETAILS ---
        Map<String, Object> section5 = new LinkedHashMap<>();
        List<Map<String, Object>> testers = new ArrayList<>();
        if (p.getAssignedPentesters() != null) {
            for (User u : p.getAssignedPentesters()) {
                Map<String, Object> t = new LinkedHashMap<>();
                t.put("name", u.getFirstName() + " " + u.getLastName());
                t.put("designation", u.getRole() != null ? u.getRole() : "Pentester");
                t.put("qualification", u.getQualification() != null ? u.getQualification() : "Certified Professional");
                testers.add(t);
            }
        }
        section5.put("testers", testers);
        
        if (p.getReportApprover() != null) {
            User a = p.getReportApprover();
            section5.put("approverName", a.getFirstName() + " " + a.getLastName());
        } else {
            section5.put("approverName", "Authorized Signatory");
        }
        masterPackage.put("section5", section5);

        // --- SECTION 6: PENTESTING ORG DETAILS ---
        Map<String, Object> section6 = new LinkedHashMap<>();
        section6.put("orgName", p.getOrganizationName() != null ? p.getOrganizationName() : "N/A");
        section6.put("headquarterAddress", p.getOrganizationAddress() != null ? p.getOrganizationAddress() : "N/A");
        section6.put("officialEmail", p.getOrganizationEmail() != null ? p.getOrganizationEmail() : "N/A");
        if (hasValue(p.getOrganizationLogo())) {
            String imgId = "LOGO_ORG";
            imageLibrary.put(imgId, p.getOrganizationLogo());
            section6.put("orgLogoId", imgId);
        }
        masterPackage.put("section6", section6);

        // --- SECTION 7: PENTEST METHODOLOGY ---
        Map<String, Object> section7 = new LinkedHashMap<>();
        section7.put("methodologyText", p.getMethodology() != null ? p.getMethodology() : "");
        List<String> methImgIds = new ArrayList<>();
        if (hasValue(p.getSelectedMethodologyImages())) {
            for (String mid : p.getSelectedMethodologyImages().split(",")) {
                String b64 = resolvePredefinedMethodologyImage(mid);
                if (b64 != null) {
                    String imgId = "METHOD_" + imgCounter++;
                    imageLibrary.put(imgId, b64);
                    methImgIds.add(imgId);
                }
            }
        }
        if (hasValue(p.getMethodologyImage())) {
            try {
                List<String> customImages = objectMapper.readValue(p.getMethodologyImage(), List.class);
                for (String b64 : customImages) {
                    if (b64 != null && !b64.isEmpty()) {
                        String imgId = "METHOD_CUSTOM_" + imgCounter++;
                        imageLibrary.put(imgId, b64);
                        methImgIds.add(imgId);
                    }
                }
            } catch (Exception e) {
                // Ignore parsing errors for custom images
            }
        }
        section7.put("methodologyImageIds", methImgIds);
        section7.put("selectedFramework", p.getSelectedOwaspCategories() != null ? Arrays.asList(p.getSelectedOwaspCategories().split("\\|\\|")) : new ArrayList<>());
        masterPackage.put("section7", section7);

        // --- SECTION 8: PENTEST SUMMARY ---
        Map<String, Object> section8 = new LinkedHashMap<>();
        section8.put("executiveSummary", p.getExecutiveSummary() != null ? p.getExecutiveSummary() : "");
        
        List<Map<String, String>> summaryTable = new ArrayList<>();
        List<Vulnerability> vs = p.getVulnerabilities() != null ? p.getVulnerabilities() : new ArrayList<>();
        for (Vulnerability v : vs) {
            summaryTable.add(Map.of("title", v.getTitle(), "severity", v.getSeverity() != null ? v.getSeverity() : "Info"));
        }
        section8.put("riskSummaryTable", summaryTable);

        section8.put("severityMetrics", Map.of(
            "CRITICAL", vs.stream().filter(v -> "Critical".equalsIgnoreCase(v.getSeverity())).count(),
            "HIGH", vs.stream().filter(v -> "High".equalsIgnoreCase(v.getSeverity())).count(),
            "MEDIUM", vs.stream().filter(v -> "Medium".equalsIgnoreCase(v.getSeverity())).count(),
            "LOW", vs.stream().filter(v -> "Low".equalsIgnoreCase(v.getSeverity())).count(),
            "INFO", vs.stream().filter(v -> "Info".equalsIgnoreCase(v.getSeverity()) || "Informational".equalsIgnoreCase(v.getSeverity())).count()
        ));

        try { 
            section8.put("severityMatrix", hasValue(p.getSeverityDefinitions()) ? objectMapper.readValue(p.getSeverityDefinitions(), List.class) : new ArrayList<>()); 
        } catch (Exception e) { 
            section8.put("severityMatrix", new ArrayList<>()); 
        }
        masterPackage.put("section8", section8);

        // --- SECTION 9: VULNERABILITIES IN DETAIL ---
        List<Map<String, Object>> findings = new ArrayList<>();
        if (p.getVulnerabilities() != null) {
            for (Vulnerability v : p.getVulnerabilities()) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("refId", "VULN-" + String.format("%03d", v.getId()));
                f.put("title", v.getTitle());
                f.put("severity", v.getSeverity());
                f.put("cvssScore", v.getCvssScore());
                f.put("cvssVector", v.getCvssVector());
                f.put("status", v.getStatus());
                f.put("cwe", v.getCweReference());
                f.put("owasp", v.getOwasp());
                f.put("description", v.getDescription());
                f.put("impact", v.getImpact());
                f.put("mitigation", v.getMitigation());
                f.put("evidenceMode", v.getEvidenceMode());
                f.put("globalFileName", v.getFileName());
                f.put("globalLineNumber", v.getLineNumber());
                f.put("globalRequestResponse", v.getRequestResponse());
                if (hasValue(v.getCodeSnippet())) {
                    String imgId = "SNIPPET_" + v.getId();
                    imageLibrary.put(imgId, v.getCodeSnippet());
                    f.put("codeSnippetImageId", imgId);
                }

                List<Map<String, Object>> steps = new ArrayList<>();
                if (v.getSteps() != null) {
                    for (VulnerabilityStep s : v.getSteps()) {
                        Map<String, Object> st = new LinkedHashMap<>();
                        st.put("order", s.getStepNumber());
                        st.put("description", s.getDescription());
                        st.put("request", s.getRequest());
                        st.put("response", s.getResponse());
                        st.put("fileName", s.getFileName());
                        st.put("lineNumber", s.getLineNumber());
                        
                        List<String> stepImgIds = new ArrayList<>();
                        if (s.getImagePaths() != null) {
                            for (String imgName : s.getImagePaths()) {
                                String b64 = encodeFileToBase64(v.getPocFolderPath(), imgName);
                                if (b64 != null) {
                                    String imgId = "VULN_POC_" + imgCounter++;
                                    imageLibrary.put(imgId, b64);
                                    stepImgIds.add(imgId);
                                }
                            }
                        }
                        st.put("pocImageIds", stepImgIds);
                        steps.add(st);
                    }
                }
                f.put("reproductionSteps", steps);
                findings.add(f);
            }
        }
        masterPackage.put("section9", Map.of("vulnerabilities", findings));

        // --- SECTION 10: CONCLUSION ---
        masterPackage.put("section10", Map.of("conclusion", p.getConclusion() != null ? p.getConclusion() : ""));

        // Global Image Library
        masterPackage.put("imageLibrary", imageLibrary);

        return masterPackage;
    }

    private boolean hasValue(String s) {
        return s != null && !s.trim().isEmpty();
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
