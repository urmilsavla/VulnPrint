package com.vulnprint;

import com.vulnprint.model.User;
import com.vulnprint.repository.PentestRepository;
import com.vulnprint.repository.VulnerabilityRepository;
import com.vulnprint.repository.AlertRepository;
import com.vulnprint.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;

import com.vulnprint.model.Permission;
import com.vulnprint.model.Role;
import com.vulnprint.repository.PermissionRepository;
import com.vulnprint.repository.RoleRepository;
import com.vulnprint.security.AppSecurityGuard;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import com.vulnprint.security.AppSecurityGuard;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private PentestRepository pentestRepository;
    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;
    @Autowired
    private AlertRepository alertRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private PermissionRepository permissionRepository;
    @Autowired
    private com.vulnprint.repository.SystemConfigRepository systemConfigRepository;
    
    @Autowired
    private AppSecurityGuard guard;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public void run(String... args) throws Exception {
        initializeAppSecurityGuard();
        initializeRoles();
        initializeUsers();
        initializeConfigs();
    }

    @Transactional
    public void initializeAppSecurityGuard() {
        createPermission(AppSecurityGuard.VIEW_DASHBOARD, "Access the executive dashboard and global metrics.");
        createPermission(AppSecurityGuard.VIEW_ALERTS, "View system-wide notifications and security alerts.");
        createPermission(AppSecurityGuard.MANAGE_ALERTS, "Mark alerts as read or clear system notifications.");
        
        createPermission(AppSecurityGuard.VIEW_ASSIGNED_PROJECTS, "See only the projects you are working on.");
        createPermission(AppSecurityGuard.VIEW_ALL_PROJECTS, "See every project in the system.");
        createPermission(AppSecurityGuard.ADD_PROJECT, "Create a new project record.");
        createPermission(AppSecurityGuard.EDIT_ASSIGNED_PROJECTS, "Change details of projects assigned to you.");
        createPermission(AppSecurityGuard.EDIT_ALL_PROJECTS, "Change details of any project in the system.");
        createPermission(AppSecurityGuard.DELETE_ASSIGNED_PROJECTS, "Delete projects you are assigned to.");
        createPermission(AppSecurityGuard.DELETE_ALL_PROJECTS, "Permanently remove any project record.");
        createPermission(AppSecurityGuard.CHANGE_PENTEST_STATUS, "Update if a project is Active, Pending, or Completed.");
        
        createPermission(AppSecurityGuard.MANAGE_REPORT_DESIGN, "Edit report logos, methodology, and disclaimers.");
        createPermission(AppSecurityGuard.GENERATE_REPORT, "Create and download the final PDF/Doc report.");
        
        createPermission(AppSecurityGuard.VIEW_ASSIGNED_VULNS, "Read and view vulnerability findings in assigned projects.");
        createPermission(AppSecurityGuard.VIEW_ALL_VULNS, "Read and view any vulnerability finding in the system.");
        createPermission(AppSecurityGuard.ADD_VULNERABILITY, "Add a new vulnerability finding to a project.");
        createPermission(AppSecurityGuard.EDIT_ASSIGNED_VULNS, "Edit vulnerabilities in projects assigned to you.");
        createPermission(AppSecurityGuard.EDIT_ALL_VULNS, "Edit any vulnerability in the system.");
        createPermission(AppSecurityGuard.DELETE_ASSIGNED_VULNS, "Remove a vulnerability finding from an assigned project.");
        createPermission(AppSecurityGuard.DELETE_ALL_VULNS, "Permanently remove any vulnerability finding.");
        createPermission(AppSecurityGuard.APPROVE_ASSIGNED_VULNS, "Approve or reject findings in assigned projects.");
        createPermission(AppSecurityGuard.APPROVE_ALL_VULNS, "Act as a global Approver to accept or reject findings.");
        
        createPermission(AppSecurityGuard.CHANGE_VULN_REPORTING_STATUS, "Update the reporting status (e.g. Sent for Approval).");
        createPermission(AppSecurityGuard.CHANGE_VULN_STATUS, "Update the technical status (e.g. Open, Fixed).");
        
        createPermission(AppSecurityGuard.VIEW_USERS, "See the list of all people using the system.");
        createPermission(AppSecurityGuard.MANAGE_USERS, "Create new user accounts and edit profiles.");
        createPermission(AppSecurityGuard.MANAGE_ACCESS, "Configure Roles and specific User Permission keys.");
        createPermission(AppSecurityGuard.ENABLE_2FA, "Enforce Multi-Factor Authentication for the user.");
        createPermission(AppSecurityGuard.MANAGE_MICROSERVICES, "Enable/Disable the external Vulnerability Database.");
        createPermission(AppSecurityGuard.EDIT_MY_PROFILE, "Update your own name and profile information.");
        createPermission(AppSecurityGuard.RESET_PASSWORD, "Change login passwords for yourself or others.");
    }

    private void createPermission(String name, String desc) {
        if (permissionRepository.findByName(name).isEmpty()) {
            permissionRepository.save(new Permission(name, desc));
        }
    }

    @Transactional
    public void initializeRoles() {
        // Upsert Administrator Role
        Role adminRole = roleRepository.findByName("Administrator").orElseGet(() -> new Role("Administrator"));
        
        // Assign all permissions EXCEPT 2FA
        Set<Permission> allPerms = new HashSet<>(permissionRepository.findAll());
        Set<Permission> filteredPerms = allPerms.stream()
                .filter(p -> !p.getName().equals(AppSecurityGuard.ENABLE_2FA))
                .collect(Collectors.toSet());
        
        adminRole.setPermissions(filteredPerms);
        roleRepository.save(adminRole);
        System.out.println("[SYSTEM] Administrator Role configured (2FA Disabled).");
    }

    @Transactional
    public void initializeUsers() {
        Role adminRole = roleRepository.findByName("Administrator").orElse(null);
        String email = "urmilsavla108@gmail.com";
        String pass = "VulPrintAdmin08$";
        
        // Upsert Primary Administrator
        User owner = userRepository.findByEmail(email).orElseGet(() -> {
            User u = new User();
            u.setEmail(email);
            return u;
        });

        owner.setPassword(guard.hashPassword(pass));
        owner.setFirstName("Urmil");
        owner.setLastName("Savla");
        owner.setRole(adminRole);
        owner.setEnabled(true);
        owner.setStatus(User.AccountStatus.ACTIVE);
        
        userRepository.save(owner);
        System.out.println("[SYSTEM] Primary Administrator updated: " + email);
    }

    private User createUser(String pass, String email, String first, String last, Role role) {
        User u = new User();
        u.setPassword(guard.hashPassword(pass)); 
        u.setEmail(email); u.setFirstName(first); u.setLastName(last); u.setRole(role);
        return userRepository.save(u);
    }

    @Transactional
    public void initializeConfigs() {
        if (systemConfigRepository.findAll().isEmpty()) {
            systemConfigRepository.save(new com.vulnprint.model.SystemConfig("repgen_enabled", "false"));
            systemConfigRepository.save(new com.vulnprint.model.SystemConfig("vulndb_enabled", "false"));
            systemConfigRepository.save(new com.vulnprint.model.SystemConfig("vulndb_url", ""));
            systemConfigRepository.save(new com.vulnprint.model.SystemConfig("repgen_url", ""));
        }
    }
}
