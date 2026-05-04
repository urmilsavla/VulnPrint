package com.vulnprint.controller;

import com.vulnprint.model.Organization;
import com.vulnprint.model.User;
import com.vulnprint.repository.OrganizationRepository;
import com.vulnprint.service.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/organization")
public class OrgRestController {

    @Autowired
    private OrganizationRepository organizationRepository;
    
    @Autowired
    private SecurityUtils securityUtils;

    @GetMapping
    public ResponseEntity<?> getSettings(@RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "MANAGE_REPORT_DESIGN")) {
            return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        }
        List<Organization> all = organizationRepository.findAll();
        if (all.isEmpty()) {
            Organization org = new Organization();
            org.setName("VulnPrint Security");
            return ResponseEntity.ok(org);
        }
        return ResponseEntity.ok(all.get(0));
    }

    @PutMapping
    public ResponseEntity<?> updateSettings(@RequestBody Organization org, @RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "MANAGE_REPORT_DESIGN")) {
            return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        }

        // Encode inputs to prevent XSS
        org.setName(securityUtils.encodeForHTML(org.getName()));
        org.setEmail(securityUtils.encodeForHTML(org.getEmail()));
        org.setPhone(securityUtils.encodeForHTML(org.getPhone()));
        org.setAddress(securityUtils.encodeForHTML(org.getAddress()));
        org.setLegalName(securityUtils.encodeForHTML(org.getLegalName()));

        List<Organization> all = organizationRepository.findAll();
        if (!all.isEmpty()) {
            org.setId(all.get(0).getId());
        }
        return ResponseEntity.ok(organizationRepository.save(org));
    }
}
