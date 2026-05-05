package com.vulnprint.service;

import com.vulnprint.model.Pentest;
import com.vulnprint.model.User;
import com.vulnprint.model.Vulnerability;
import com.vulnprint.repository.PentestRepository;
import com.vulnprint.repository.VulnerabilityRepository;
import com.vulnprint.security.Permissions;
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

    @Autowired
    private SecurityUtils securityUtils;

    private User getCurrentUser() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof User) {
            return (User) principal;
        }
        return null;
    }

    // --- Project Permissions ---

    public boolean canViewProject(Long pentestId) {
        User user = getCurrentUser();
        if (user == null) return false;
        if (securityUtils.hasPermission(user, Permissions.VIEW_ALL_PROJECTS)) return true;
        return securityUtils.hasPermission(user, Permissions.VIEW_ASSIGNED_PROJECTS) && isAssignedToPentest(pentestId);
    }

    public boolean canEditProject(Long pentestId) {
        User user = getCurrentUser();
        if (user == null) return false;
        if (securityUtils.hasPermission(user, Permissions.EDIT_ALL_PROJECTS)) return true;
        return securityUtils.hasPermission(user, Permissions.EDIT_ASSIGNED_PROJECTS) && isAssignedToPentest(pentestId);
    }

    public boolean canDeleteProject(Long pentestId) {
        User user = getCurrentUser();
        if (user == null) return false;
        if (securityUtils.hasPermission(user, Permissions.DELETE_ALL_PROJECTS)) return true;
        return securityUtils.hasPermission(user, Permissions.DELETE_ASSIGNED_PROJECTS) && isAssignedToPentest(pentestId);
    }

    // --- Vulnerability Permissions ---

    public boolean canViewVuln(Long vulnId) {
        User user = getCurrentUser();
        if (user == null) return false;
        if (securityUtils.hasPermission(user, Permissions.VIEW_ALL_VULNS)) return true;
        return securityUtils.hasPermission(user, Permissions.VIEW_ASSIGNED_VULNS) && isAssignedToVuln(vulnId);
    }

    public boolean canEditVuln(Long vulnId) {
        User user = getCurrentUser();
        if (user == null) return false;
        if (securityUtils.hasPermission(user, Permissions.EDIT_ALL_VULNS)) return true;
        return securityUtils.hasPermission(user, Permissions.EDIT_ASSIGNED_VULNS) && isAssignedToVuln(vulnId);
    }

    public boolean canDeleteVuln(Long vulnId) {
        User user = getCurrentUser();
        if (user == null) return false;
        if (securityUtils.hasPermission(user, Permissions.DELETE_ALL_VULNS)) return true;
        return securityUtils.hasPermission(user, Permissions.DELETE_ASSIGNED_VULNS) && isAssignedToVuln(vulnId);
    }

    public boolean canApproveVuln(Long vulnId) {
        User user = getCurrentUser();
        if (user == null) return false;
        if (securityUtils.hasPermission(user, Permissions.APPROVE_ALL_VULNS)) return true;
        return securityUtils.hasPermission(user, Permissions.APPROVE_ASSIGNED_VULNS) && isAssignedToVuln(vulnId);
    }

    // --- Internal Assignment Helpers ---

    public boolean isAssignedToPentest(Long pentestId) {
        User currentUser = getCurrentUser();
        if (currentUser == null || pentestId == null) return false;

        Optional<Pentest> pentest = pentestRepository.findById(pentestId);
        return pentest.map(p -> p.getAssignedPentesters().stream()
                .anyMatch(u -> u.getId().equals(currentUser.getId())))
                .orElse(false);
    }

    public boolean isAssignedToVuln(Long vulnId) {
        User currentUser = getCurrentUser();
        if (currentUser == null || vulnId == null) return false;

        Optional<Vulnerability> vuln = vulnerabilityRepository.findById(vulnId);
        return vuln.map(v -> v.getPentest() != null && v.getPentest().getAssignedPentesters().stream()
                .anyMatch(u -> u.getId().equals(currentUser.getId())))
                .orElse(false);
    }

    public boolean isSelf(Long userId) {
        User currentUser = getCurrentUser();
        return currentUser != null && currentUser.getId().equals(userId);
    }
}
