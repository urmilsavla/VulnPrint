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

@Service
public class ReportDataService {

    @Autowired
    private PentestRepository pentestRepository;

    @Autowired
    private ResourceLoader resourceLoader;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Transactional(readOnly = true)
    public Map<String, Object> getReportGenerationData(Long pentestId) {
        Pentest p = pentestRepository.findById(pentestId)
                .orElseThrow(() -> new RuntimeException("Assessment ID " + pentestId + " not found."));

        Map<String, Object> repGenPackage = new LinkedHashMap<>();
        Map<String, String> imageLibrary = new LinkedHashMap<>();
        int imgCounter = 1;
        
        // --- 1. PENTEST DETAILS ---
        Map<String, Object> pentestDetails = new LinkedHashMap<>();
        pentestDetails.put("projectName", hasValue(p.getPentestName()) ? p.getPentestName() : "N/A");
        pentestDetails.put("pentestType", hasValue(p.getPentestType()) ? p.getPentestType() : "N/A");
        
        List<Map<String, String>> technicalScopes = new ArrayList<>();
        if (hasValue(p.getTarget())) technicalScopes.add(Map.of("technicalScopeKey", "Target", "technicalScopeValue", p.getTarget()));
        if (hasValue(p.getUrl())) technicalScopes.add(Map.of("technicalScopeKey", "URL", "technicalScopeValue", p.getUrl()));
        if (hasValue(p.getTechStack())) technicalScopes.add(Map.of("technicalScopeKey", "Tech Stack", "technicalScopeValue", p.getTechStack()));
        if (hasValue(p.getIpRanges())) technicalScopes.add(Map.of("technicalScopeKey", "IP Ranges", "technicalScopeValue", p.getIpRanges()));
        if (hasValue(p.getPackageName())) technicalScopes.add(Map.of("technicalScopeKey", "Package Name", "technicalScopeValue", p.getPackageName()));
        if (hasValue(p.getOsType())) technicalScopes.add(Map.of("technicalScopeKey", "OS Type", "technicalScopeValue", p.getOsType()));
        if (hasValue(p.getApiDomain())) technicalScopes.add(Map.of("technicalScopeKey", "API Domain", "technicalScopeValue", p.getApiDomain()));
        if (hasValue(p.getApiType())) technicalScopes.add(Map.of("technicalScopeKey", "API Type", "technicalScopeValue", p.getApiType()));
        if (hasValue(p.getTargetType())) technicalScopes.add(Map.of("technicalScopeKey", "Target Type", "technicalScopeValue", p.getTargetType()));
        if (hasValue(p.getRepoUrl())) technicalScopes.add(Map.of("technicalScopeKey", "Repo URL", "technicalScopeValue", p.getRepoUrl()));
        if (hasValue(p.getBranchName())) technicalScopes.add(Map.of("technicalScopeKey", "Branch", "technicalScopeValue", p.getBranchName()));
        if (hasValue(p.getLanguage())) technicalScopes.add(Map.of("technicalScopeKey", "Language", "technicalScopeValue", p.getLanguage()));
        if (hasValue(p.getVersion())) technicalScopes.add(Map.of("technicalScopeKey", "Version", "technicalScopeValue", p.getVersion()));
        
        pentestDetails.put("technicalScopes", technicalScopes);
        pentestDetails.put("projectInitiationDate", p.getCreatedDate() != null ? p.getCreatedDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd")) : "N/A");
        pentestDetails.put("projectCompletionDate", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        repGenPackage.put("pentestDetails", pentestDetails);

        // --- 2. CLIENT DETAILS ---
        Map<String, Object> clientDetails = new LinkedHashMap<>();
        clientDetails.put("clientName", p.getClientName() != null ? p.getClientName() : "N/A");
        clientDetails.put("clientSpocName", p.getClientSpocName() != null ? p.getClientSpocName() : "N/A");
        clientDetails.put("clientSpocContact", p.getClientSpocContact() != null ? p.getClientSpocContact() : "N/A");
        clientDetails.put("reportRecipientName", p.getSubmittedToName() != null ? p.getSubmittedToName() : "N/A");
        clientDetails.put("reportRecipientDesignation", p.getSubmittedToDesignation() != null ? p.getSubmittedToDesignation() : "N/A");
        
        String cLogo = p.getClientLogo();
        if (cLogo != null && !cLogo.isEmpty()) {
            String imgId = "LOGO_CLIENT";
            imageLibrary.put(imgId, cLogo);
            clientDetails.put("clientLogoId", imgId);
        }
        repGenPackage.put("clientDetails", clientDetails);

        // --- 3. PENTEST CONDUCTING ORGANIZATION DETAILS ---
        Map<String, Object> conductingOrganizationDetails = new LinkedHashMap<>();
        conductingOrganizationDetails.put("organizationName", hasValue(p.getOrganizationName()) ? p.getOrganizationName() : "N/A");
        conductingOrganizationDetails.put("organizationLegalName", hasValue(p.getOrganizationLegalName()) ? p.getOrganizationLegalName() : "N/A");
        conductingOrganizationDetails.put("officialEmail", hasValue(p.getOrganizationEmail()) ? p.getOrganizationEmail() : "N/A");
        conductingOrganizationDetails.put("officialContactNumber", hasValue(p.getOrganizationPhone()) ? p.getOrganizationPhone() : "N/A");
        conductingOrganizationDetails.put("headquartersAddress", hasValue(p.getOrganizationAddress()) ? p.getOrganizationAddress() : "N/A");
        
        if (p.getReportApprover() != null) {
            User approver = p.getReportApprover();
            conductingOrganizationDetails.put("reportApproverName", approver.getFirstName() + " " + approver.getLastName());
            conductingOrganizationDetails.put("reportApproverDesignation", approver.getRole() != null ? approver.getRole() : "Authorized Signatory");
        } else {
            conductingOrganizationDetails.put("reportApproverName", "N/A");
            conductingOrganizationDetails.put("reportApproverDesignation", "N/A");
        }

        String oLogo = p.getOrganizationLogo();
        if (oLogo != null && !oLogo.isEmpty()) {
            String imgId = "LOGO_ORG";
            imageLibrary.put(imgId, oLogo);
            conductingOrganizationDetails.put("organizationLogoId", imgId);
        }
        repGenPackage.put("pentestConductingOrgDetails", conductingOrganizationDetails);

        // --- PENTEST CONDUCTING TESTERS ---
        List<Map<String, Object>> pentestConductingTesters = new ArrayList<>();
        if (p.getAssignedPentesters() != null) {
            List<User> testers = p.getAssignedPentesters();
            for (int i = 0; i < testers.size(); i++) {
                User u = testers.get(i);
                Map<String, Object> t = new LinkedHashMap<>();
                t.put("srNo", i + 1);
                t.put("name", u.getFirstName() + " " + u.getLastName());
                t.put("qualification", u.getQualification() != null ? u.getQualification() : "N/A");
                pentestConductingTesters.add(t);
            }
        }
        repGenPackage.put("pentestConductingTesters", pentestConductingTesters);

        // --- 4. DISCLAIMER AND CONCLUSION ---
        Map<String, Object> disclaimerAndConclusion = new LinkedHashMap<>();
        disclaimerAndConclusion.put("disclaimer", p.getDisclaimer() != null ? p.getDisclaimer() : "");
        disclaimerAndConclusion.put("conclusion", p.getConclusion() != null ? p.getConclusion() : "");
        repGenPackage.put("disclaimerAndConclusion", disclaimerAndConclusion);

        // --- 5. PENTEST EXECUTIVE SUMMARY ---
        Map<String, Object> pentestExecutiveSummary = new LinkedHashMap<>();
        pentestExecutiveSummary.put("executiveSummary", p.getExecutiveSummary() != null ? p.getExecutiveSummary() : "");
        pentestExecutiveSummary.put("riskSummary", p.getRiskSummary() != null ? p.getRiskSummary() : "");
        
        if (hasValue(p.getRiskOverviewChart())) {
            String chartId = "CHART_RISK_OVERVIEW";
            imageLibrary.put(chartId, p.getRiskOverviewChart());
            pentestExecutiveSummary.put("riskChartImageId", chartId);
        }

        List<Vulnerability> vs = p.getVulnerabilities() != null ? p.getVulnerabilities() : new ArrayList<>();
        pentestExecutiveSummary.put("severityMetrics", Map.of(
            "CRITICAL", vs.stream().filter(v -> "Critical".equalsIgnoreCase(v.getSeverity())).count(),
            "HIGH", vs.stream().filter(v -> "High".equalsIgnoreCase(v.getSeverity())).count(),
            "MEDIUM", vs.stream().filter(v -> "Medium".equalsIgnoreCase(v.getSeverity())).count(),
            "LOW", vs.stream().filter(v -> "Low".equalsIgnoreCase(v.getSeverity())).count(),
            "INFO", vs.stream().filter(v -> "Info".equalsIgnoreCase(v.getSeverity()) || "Informational".equalsIgnoreCase(v.getSeverity())).count()
        ));

        List<Map<String, Object>> summaryTable = new ArrayList<>();
        for (int i = 0; i < vs.size(); i++) {
            Vulnerability v = vs.get(i);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("srNo", i + 1);
            row.put("title", v.getTitle());
            row.put("severity", v.getSeverity() != null ? v.getSeverity() : "Info");
            summaryTable.add(row);
        }
        pentestExecutiveSummary.put("vulnerabilitiesSummaryTable", summaryTable);
        repGenPackage.put("pentestExecutiveSummary", pentestExecutiveSummary);

        // --- 6. PENTEST METHODOLOGY AND FRAMEWORKS ---
        Map<String, Object> pentestMethodologyAndFrameworks = new LinkedHashMap<>();
        pentestMethodologyAndFrameworks.put("methodologyDisplayMode", p.getMethodologyDisplayMode() != null ? p.getMethodologyDisplayMode() : "BOTH");
        pentestMethodologyAndFrameworks.put("methodologyText", p.getMethodology() != null ? p.getMethodology() : "");
        
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
            } catch (Exception e) { }
        }
        pentestMethodologyAndFrameworks.put("methodologyImageIds", methImgIds);
        
        String frameworkData = hasValue(p.getSelectedOwaspCategories()) ? p.getSelectedOwaspCategories() : p.getOwaspTop10();
        List<Map<String, Object>> selectedFrameworks = new ArrayList<>();
        if (hasValue(frameworkData)) {
            String[] parts = frameworkData.contains("||") ? frameworkData.split("\\|\\|") : frameworkData.split(",");
            for (String part : parts) {
                if (hasValue(part)) {
                    selectedFrameworks.add(resolveFrameworkDetails(part.trim()));
                }
            }
        }
        pentestMethodologyAndFrameworks.put("selectedFrameworks", selectedFrameworks);
        repGenPackage.put("pentestMethodologyAndFrameworks", pentestMethodologyAndFrameworks);

        // --- 7. VULNERABILITY DETAILS (Metadata) ---
        List<Map<String, Object>> vulnerabilityDetailsList = new ArrayList<>();
        for (int i = 0; i < vs.size(); i++) {
            Vulnerability v = vs.get(i);
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("srNo", i + 1);
            f.put("referenceId", "VULN-" + String.format("%03d", v.getId()));
            f.put("vulnerabilityTitle", v.getTitle());
            f.put("severity", v.getSeverity());
            f.put("cvssScore", v.getCvssScore());
            f.put("cvssVector", v.getCvssVector());
            f.put("status", v.getStatus());
            f.put("cweReference", v.getCweReference());
            f.put("owaspReference", v.getOwasp());
            f.put("description", v.getDescription());
            f.put("impact", v.getImpact());
            f.put("mitigation", v.getMitigation());
            vulnerabilityDetailsList.add(f);
        }
        repGenPackage.put("vulnerabilityDetailsList", vulnerabilityDetailsList);

        // --- 8. VULNERABILITY EVIDENCES (Technical Deep Dive) ---
        List<Map<String, Object>> vulnerabilityEvidencesList = new ArrayList<>();
        for (Vulnerability v : vs) {
            Map<String, Object> ev = new LinkedHashMap<>();
            ev.put("vulnerabilityTitle", v.getTitle());
            ev.put("referenceId", "VULN-" + String.format("%03d", v.getId()));
            ev.put("evidenceMode", v.getEvidenceMode());
            ev.put("globalFileName", v.getFileName());
            ev.put("globalLineNumber", v.getLineNumber());
            ev.put("globalRequestResponse", v.getRequestResponse());
            
            if (hasValue(v.getCodeSnippet())) {
                String imgId = "SNIPPET_" + v.getId();
                imageLibrary.put(imgId, v.getCodeSnippet());
                ev.put("codeSnippetImageId", imgId);
            }

            List<Map<String, Object>> reproductionSteps = new ArrayList<>();
            if (v.getSteps() != null) {
                for (int j = 0; j < v.getSteps().size(); j++) {
                    VulnerabilityStep s = v.getSteps().get(j);
                    Map<String, Object> st = new LinkedHashMap<>();
                    st.put("stepLabel", "Step " + (j + 1));
                    st.put("stepNumber", s.getStepNumber());
                    st.put("stepDescription", s.getDescription());
                    st.put("requestData", s.getRequest());
                    st.put("responseData", s.getResponse());
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
                    st.put("proofOfConceptImageIds", stepImgIds);
                    reproductionSteps.add(st);
                }
            }
            ev.put("reproductionSteps", reproductionSteps);
            vulnerabilityEvidencesList.add(ev);
        }
        repGenPackage.put("vulnerabilityEvidencesList", vulnerabilityEvidencesList);

        // Global Image Library
        repGenPackage.put("imageLibrary", imageLibrary);
        
        return repGenPackage;
    }

    private boolean hasValue(String s) {
        return s != null && !s.trim().isEmpty();
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

    private Map<String, Object> resolveFrameworkDetails(String id) {
        Map<String, List<String>> frameworkItems = Map.of(
            "web", List.of("A01:2021 – Broken Access Control", "A02:2021 – Cryptographic Failures", "A03:2021 – Injection", "A04:2021 – Insecure Design", "A05:2021 – Security Misconfiguration", "A06:2021 – Vulnerable and Outdated Components", "A07:2021 – Identification and Authentication Failures", "A08:2021 – Software and Data Integrity Failures", "A09:2021 – Security Logging and Monitoring Failures", "A10:2021 – Server-Side Request Forgery (SSRF)"),
            "api", List.of("API1:2023 – Broken Object Level Authorization (BOLA)", "API2:2023 – Broken Authentication", "API3:2023 – Broken Object Property Level Authorization", "API4:2023 – Unrestricted Resource Consumption", "API5:2023 – Broken Function Level Authorization", "API6:2023 – Unrestricted Access to Sensitive Business Flows", "API7:2023 – Server-Side Request Forgery (SSRF)", "API8:2023 – Security Misconfiguration", "API9:2023 – Improper Inventory Management", "API10:2023 – Unsafe Consumption of APIs"),
            "mobile", List.of("M1 – Improper Credential Usage", "M2 – Inadequate Supply Chain Security", "M3 – Insecure Authentication/Authorization", "M4 – Insufficient Input/Output Validation", "M5 – Insecure Communication", "M6 – Inadequate Privacy Controls", "M7 – Insufficient Binary Protections", "M8 – Security Misconfiguration", "M9 – Insecure Data Storage", "M10 – Insufficient Cryptography"),
            "ai", List.of("LLM01 – Prompt Injection", "LLM02 – Insecure Output Handling", "LLM03 – Training Data Poisoning", "LLM04 – Model Denial of Service", "LLM05 – Supply Chain Vulnerabilities", "LLM06 – Sensitive Information Disclosure", "LLM07 – Insecure Plugin Design", "LLM08 – Excessive Agency", "LLM09 – Overreliance", "LLM10 – Model Theft"),
            "infra", List.of("ISR01 – Outdated/Unpatched Software", "ISR02 – Insufficient Threat Detection & Response", "ISR03 – Insecure System Configurations", "ISR04 – Insecure Identity & Access Management (IAM)", "ISR05 – Insecure Use of Cryptography (Weak Ciphers)", "ISR06 – Insecure Network Segregation", "ISR07 – Default Credentials & Weak Auth", "ISR08 – Information Leakage via Metadata/Logs", "ISR09 – Insecure Remote Management (SSH/RDP)", "ISR10 – Insufficient Asset Inventory"),
            "code", List.of("CWE-79 – Cross-Site Scripting (XSS)", "CWE-787 – Out-of-bounds Write", "CWE-89 – SQL Injection", "CWE-862 – Missing Authorization", "CWE-20 – Improper Input Validation", "CWE-125 – Out-of-bounds Read", "CWE-416 – Use After Free", "CWE-352 – Cross-Site Request Forgery (CSRF)", "CWE-22 – Path Traversal", "CWE-476 – Null Pointer Dereference", "CWE-94 – Code Injection", "CWE-78 – OS Command Injection", "CWE-502 – Deserialization of Untrusted Data", "CWE-269 – Improper Privilege Management", "CWE-306 – Missing Authentication", "CWE-362 – Race Condition", "CWE-400 – Uncontrolled Resource Consumption", "CWE-611 – Improper Restriction of XML External Entity Reference (XXE)", "CWE-732 – Incorrect Permission Assignment for Critical Resource", "CWE-295 – Improper Certificate Validation", "CWE-312 – Cleartext Storage of Sensitive Information", "CWE-327 – Use of a Broken or Risky Cryptographic Algorithm", "CWE-522 – Insufficiently Protected Credentials", "CWE-601 – Open Redirect", "CWE-770 – Allocation of Resources Without Limits")
        );

        Map<String, String> titles = Map.of(
            "web", "Web Application Security Risks (OWASP Top 10: 2021)",
            "api", "API Security Risks (OWASP Top 10: 2023)",
            "mobile", "Mobile Application Security Risks (OWASP Top 10: 2024)",
            "ai", "LLM & GenAI Security Risks (OWASP Top 10: 2025 Update)",
            "infra", "Infrastructure Security (Modern Enterprise Risks)",
            "code", "Code Review/SAST (CWE Top 25: 2025)"
        );

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("frameworkId", id);
        details.put("frameworkTitle", titles.getOrDefault(id, id));
        details.put("frameworkRisks", frameworkItems.getOrDefault(id, new ArrayList<>()));
        return details;
    }
}
