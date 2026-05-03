package com.vulnprint.controller;

import com.vulnprint.service.VulnDbService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/vulndb")
public class VulnDbRestController {

    @Autowired
    private VulnDbService vulnDbService;

    @GetMapping("/search")
    public Map<String, Object> search(@RequestParam(required = false) String q,
                                     @RequestParam(required = false) String category,
                                     @RequestParam(required = false) String severity) {
        return vulnDbService.search(q, category, severity);
    }

    @GetMapping("/vulns/{slug}")
    public VulnDbService.VulnDbVulnerability getVulnerability(@PathVariable String slug) {
        return vulnDbService.getVulnerability(slug);
    }
}
