package com.vulnprint.service;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.vulnprint.model.SystemConfig;
import com.vulnprint.repository.SystemConfigRepository;
import com.vulnprint.security.AppSecurityGuard;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

@Service
public class VulnDbService {

    @Autowired
    private SystemConfigRepository systemConfigRepository;

    @Autowired
    private AppSecurityGuard guard;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.services.vulndb.default-url:http://vulndb.internal:8000}")
    private String defaultUrl;

    private RestClient getClient() {
        String baseUrl = systemConfigRepository.findById("vulndb_url")
                .map(SystemConfig::getConfigValue)
                .filter(url -> !url.isBlank())
                .orElse(defaultUrl); 
        
        // SSRF Check: Ensure the configured VulnDB URL is not targeting forbidden zones
        if (!guard.isSafeUrl(baseUrl)) {
            throw new SecurityException("SSRF Blocked: Configured VulnDB URL targets a restricted internal address.");
        }

        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        
        return RestClient.builder().baseUrl(baseUrl).build();
    }

    public Map search(String query, String category, String severity) {
        try {
            return getClient().get()
                    .uri(uriBuilder -> uriBuilder
                            .path("/api/search")
                            .queryParam("q", guard.sanitize(query))
                            .queryParam("category", guard.sanitize(category))
                            .queryParam("severity", guard.sanitize(severity))
                            .build())
                    .retrieve()
                    .body(Map.class);
        } catch (Exception e) {
            return Map.of("results", List.of(), "total", 0, "error", "VulnDB Integration Error: " + e.getMessage());
        }
    }

    public VulnDbVulnerability getVulnerability(String slug) {
        // Sanitize slug to prevent path traversal on the target microservice
        String safeSlug = guard.sanitize(slug);
        if (safeSlug != null && safeSlug.contains("..")) throw new SecurityException("Traversal attempt in slug");

        return getClient().get()
                .uri("/api/vulns/{slug}", safeSlug)
                .retrieve()
                .body(VulnDbVulnerability.class);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record VulnDbVulnerability(
            Long id,
            String slug,
            String title,
            String category,
            String severity,
            @JsonProperty("platform_tags") List<String> platformTags,
            String description,
            String impact,
            List<String> mitigations,
            @JsonProperty("cwe_ids") List<String> cweIds,
            @JsonProperty("owasp_refs") List<String> owaspRefs,
            @JsonProperty("cve_ids") List<String> cveIds,
            List<String> tags
    ) {}
}
