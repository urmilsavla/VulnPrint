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

import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api/organization")
public class OrgRestController {

    @Autowired
    private OrganizationRepository organizationRepository;
    
    @Autowired
    private SecurityUtils securityUtils;

    @GetMapping
    @PreAuthorize("hasAuthority('MANAGE_REPORT_DESIGN')")
    public ResponseEntity<?> getSettings() {
        List<Organization> all = organizationRepository.findAll();
        if (all.isEmpty()) {
            Organization org = new Organization();
            org.setName("VulnPrint Security");
            return ResponseEntity.ok(org);
        }
        return ResponseEntity.ok(all.get(0));
    }

    @PutMapping
    @PreAuthorize("hasAuthority('MANAGE_REPORT_DESIGN')")
    public ResponseEntity<?> updateSettings(@jakarta.validation.Valid @RequestBody com.vulnprint.dto.OrganizationDTO dto) {
        Organization org = new Organization();
        // Encode inputs to prevent XSS
        org.setName(securityUtils.encodeForHTML(dto.getName()));
        org.setEmail(securityUtils.encodeForHTML(dto.getEmail()));
        org.setPhone(securityUtils.encodeForHTML(dto.getPhone()));
        org.setAddress(securityUtils.encodeForHTML(dto.getAddress()));
        org.setLegalName(securityUtils.encodeForHTML(dto.getLegalName()));
        org.setLogo(dto.getLogo());

        List<Organization> all = organizationRepository.findAll();
        if (!all.isEmpty()) {
            org.setId(all.get(0).getId());
        }
        return ResponseEntity.ok(organizationRepository.save(org));
    }
}
