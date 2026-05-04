package com.vulnprint;

import com.vulnprint.model.Pentest;
import com.vulnprint.model.Vulnerability;
import com.vulnprint.model.VulnerabilityStep;
import com.vulnprint.model.Alert;
import com.vulnprint.model.User;
import com.vulnprint.repository.PentestRepository;
import com.vulnprint.repository.VulnerabilityRepository;
import com.vulnprint.repository.AlertRepository;
import com.vulnprint.repository.UserRepository;
import com.vulnprint.service.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import org.springframework.jdbc.core.JdbcTemplate;

import com.vulnprint.model.Permission;
import com.vulnprint.model.Role;
import com.vulnprint.repository.PermissionRepository;
import com.vulnprint.repository.RoleRepository;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

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
    private SecurityUtils securityUtils;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public void run(String... args) throws Exception {
        initializePermissions();
        initializeRoles();
        initializeUsers();
        initializeConfigs();
    }

    @Transactional
    public void initializePermissions() {
        createPermission("VIEW_DASHBOARD", "Access the executive dashboard and global metrics.");
        createPermission("VIEW_ALERTS", "View system-wide notifications and security alerts.");
        createPermission("MANAGE_ALERTS", "Mark alerts as read or clear system notifications.");
        createPermission("VIEW_ASSIGNED_PROJECTS", "See only the projects you are working on.");
        createPermission("VIEW_ALL_PROJECTS", "See every project in the system.");
        createPermission("ADD_PROJECT", "Create a new project record.");
        createPermission("EDIT_ASSIGNED_PROJECTS", "Change details of projects assigned to you.");
        createPermission("EDIT_ALL_PROJECTS", "Change details of any project in the system.");
        createPermission("DELETE_PROJECT", "Permanently remove a project record.");
        createPermission("CHANGE_PENTEST_STATUS", "Update if a project is Active, Pending, or Completed.");
        createPermission("MANAGE_REPORT_DESIGN", "Edit report logos, methodology, and disclaimers.");
        createPermission("VIEW_VULNERABILITIES", "Read and view vulnerability findings and evidence.");
        createPermission("ADD_VULNERABILITY", "Add a new vulnerability finding to a project.");
        createPermission("EDIT_ASSIGNED_VULNS", "Edit vulnerabilities in projects assigned to you.");
        createPermission("EDIT_ALL_VULNS", "Edit any vulnerability in the system, even if not assigned.");
        createPermission("DELETE_VULNERABILITY", "Permanently remove a vulnerability finding.");
        createPermission("APPROVE_VULNERABILITIES", "Act as an Approver to accept or reject findings.");
        createPermission("CHANGE_VULN_REPORTING_STATUS", "Update the reporting status (e.g. Sent for Approval).");
        createPermission("CHANGE_VULN_STATUS", "Update the technical status (e.g. Open, Fixed).");
        createPermission("GENERATE_REPORT", "Create and download the final PDF/Doc report.");
        createPermission("VIEW_USERS", "See the list of all people using the system.");
        createPermission("MANAGE_USERS", "Create new user accounts and edit profiles.");
        createPermission("MANAGE_ACCESS", "Configure Roles and specific User Permission keys.");
        createPermission("MANAGE_MICROSERVICES", "Enable/Disable the external Vulnerability Database.");
        createPermission("EDIT_MY_PROFILE", "Update your own name and profile information.");
        createPermission("RESET_PASSWORD", "Change login passwords for yourself or others.");
    }

    private void createPermission(String name, String desc) {
        if (permissionRepository.findByName(name).isEmpty()) {
            permissionRepository.save(new Permission(name, desc));
        }
    }

    @Transactional
    public void initializeRoles() {
        Optional<Role> adminOpt = roleRepository.findByName("Administrator");
        if (adminOpt.isEmpty()) {
            Role adminRole = new Role("Administrator");
            adminRole.setPermissions(new HashSet<>(permissionRepository.findAll()));
            roleRepository.save(adminRole);
        } else {
            // Ensure Admin always has all permissions
            Role adminRole = adminOpt.get();
            adminRole.setPermissions(new HashSet<>(permissionRepository.findAll()));
            roleRepository.save(adminRole);
        }

        if (roleRepository.findByName("Penetration Tester").isEmpty()) {
            Role testerRole = new Role("Penetration Tester");
            testerRole.setPermissions(getPermissions(
                "VIEW_DASHBOARD", "VIEW_ALERTS", "VIEW_ASSIGNED_PROJECTS", 
                "EDIT_ASSIGNED_PROJECTS", "VIEW_VULNERABILITIES", 
                "ADD_VULNERABILITY", "EDIT_ASSIGNED_VULNS", 
                "CHANGE_VULN_STATUS", "EDIT_MY_PROFILE", "RESET_PASSWORD"
            ));
            roleRepository.save(testerRole);
        }
    }

    private Set<Permission> getPermissions(String... names) {
        Set<Permission> perms = new HashSet<>();
        for (String n : names) {
            permissionRepository.findByName(n).ifPresent(perms::add);
        }
        return perms;
    }

    @Transactional
    public void initializeUsers() {
        List<User> users = userRepository.findAll();
        if (users.isEmpty()) {
            Role adminRole = roleRepository.findByName("Administrator").orElse(null);
            createUser("admin", "p455w0rd", "admin@vulnprint.local", "System", "Administrator", adminRole, "Global HQ", "Root Authority");
        } else {
            // Fix for existing users with plaintext passwords from older versions
            for (User u : users) {
                if (u.getPassword() != null && !u.getPassword().startsWith("$2a$") && !u.getPassword().startsWith("$2b$") && !u.getPassword().startsWith("$2y$")) {
                    u.setPassword(securityUtils.hashPassword(u.getPassword()));
                    userRepository.save(u);
                }
            }
        }
    }

    private User createUser(String user, String pass, String email, String first, String last, Role role, String address, String qualification) {
        User u = new User();
        u.setUsername(user); 
        u.setPassword(securityUtils.hashPassword(pass)); 
        u.setEmail(email); u.setFirstName(first); u.setLastName(last); u.setRole(role); u.setAddress(address); u.setQualification(qualification);
        return userRepository.save(u);
    }

    @Transactional
    public void initializeConfigs() {
        if (systemConfigRepository.findAll().isEmpty()) {
            systemConfigRepository.save(new com.vulnprint.model.SystemConfig("repgen_enabled", "true"));
            systemConfigRepository.save(new com.vulnprint.model.SystemConfig("vulndb_url", ""));
        }
    }
}
