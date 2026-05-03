package com.vulnprint.service;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.vulnprint.model.SystemConfig;
import com.vulnprint.repository.SystemConfigRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

@Service
public class VulnDbService {

    @Autowired
    private SystemConfigRepository systemConfigRepository;

    private RestClient getClient() {
        String baseUrl = systemConfigRepository.findById("vulndb_url")
                .map(SystemConfig::getConfigValue)
                .filter(url -> !url.isBlank())
                .orElse("http://127.0.0.1:8000");
        
        // Remove trailing slash to avoid double slashes in path
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        
        return RestClient.builder().baseUrl(baseUrl).build();
    }

    public Map<String, Object> search(String query, String category, String severity) {
        try {
            return getClient().get()
                    .uri(uriBuilder -> uriBuilder
                            .path("/api/search")
                            .queryParam("q", query)
                            .queryParam("category", category)
                            .queryParam("severity", severity)
                            .build())
                    .retrieve()
                    .body(Map.class);
        } catch (Exception e) {
            // Log or handle error - returning an empty map with error info
            return Map.of("results", List.of(), "total", 0, "error", e.getMessage());
        }
    }

    public VulnDbVulnerability getVulnerability(String slug) {
        return getClient().get()
                .uri("/api/vulns/{slug}", slug)
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
