package com.vulnprint.service;

import com.vulnprint.model.Pentest;
import com.vulnprint.model.User;
import com.vulnprint.model.Vulnerability;
import com.vulnprint.repository.PentestRepository;
import com.vulnprint.repository.VulnerabilityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service("securityService")
public class SecurityService {

    @Autowired
    private PentestRepository pentestRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    public boolean isAssignedToPentest(Long pentestId) {
        User currentUser = getCurrentUser();
        if (currentUser == null) return false;

        // Admins can see everything (assuming ROLE_Admin or similar)
        if (currentUser.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_Admin"))) {
            return true;
        }

        Optional<Pentest> pentest = pentestRepository.findById(pentestId);
        return pentest.map(p -> p.getAssignedPentesters().stream()
                .anyMatch(u -> u.getId().equals(currentUser.getId())))
                .orElse(false);
    }

    public boolean isAssignedToVuln(Long vulnId) {
        User currentUser = getCurrentUser();
        if (currentUser == null) return false;

        if (currentUser.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_Admin"))) {
            return true;
        }

        Optional<Vulnerability> vuln = vulnerabilityRepository.findById(vulnId);
        return vuln.map(v -> v.getPentest() != null && v.getPentest().getAssignedPentesters().stream()
                .anyMatch(u -> u.getId().equals(currentUser.getId())))
                .orElse(false);
    }

    public boolean isSelf(Long userId) {
        User currentUser = getCurrentUser();
        return currentUser != null && currentUser.getId().equals(userId);
    }

    private User getCurrentUser() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof User) {
            return (User) principal;
        }
        return null;
    }
}
