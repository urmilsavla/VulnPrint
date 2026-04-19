package com.vulnprint.controller;

import com.vulnprint.model.Organization;
import com.vulnprint.repository.OrganizationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/organization")
public class OrgRestController {

    @Autowired
    private OrganizationRepository organizationRepository;

    @GetMapping
    public Organization getSettings() {
        List<Organization> all = organizationRepository.findAll();
        if (all.isEmpty()) {
            Organization org = new Organization();
            org.setName("VulnPrint Security");
            return org;
        }
        return all.get(0);
    }

    @PutMapping
    public Organization updateSettings(@RequestBody Organization org) {
        List<Organization> all = organizationRepository.findAll();
        if (!all.isEmpty()) {
            org.setId(all.get(0).getId());
        }
        return organizationRepository.save(org);
    }
}
