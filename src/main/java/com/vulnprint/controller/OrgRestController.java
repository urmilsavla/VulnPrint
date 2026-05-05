package com.vulnprint.controller;

import com.vulnprint.model.Organization;
import com.vulnprint.model.User;
import com.vulnprint.repository.OrganizationRepository;
import com.vulnprint.security.AppSecurityGuard;
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
    private AppSecurityGuard guard;

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
        // Force centralized sanitization on all fields
        org.setName(guard.sanitize(dto.getName()));
        org.setEmail(guard.sanitize(dto.getEmail()));
        org.setPhone(guard.sanitize(dto.getPhone()));
        org.setAddress(guard.sanitize(dto.getAddress()));
        org.setLegalName(guard.sanitize(dto.getLegalName()));
        org.setLogo(guard.sanitize(dto.getLogo()));

        List<Organization> all = organizationRepository.findAll();
        if (!all.isEmpty()) {
            org.setId(all.get(0).getId());
        }
        return ResponseEntity.ok(organizationRepository.save(org));
    }
}
