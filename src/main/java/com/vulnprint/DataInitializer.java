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

import com.vulnprint.security.Permissions;

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
        initializePermissions();
        initializeRoles();
        initializeUsers();
        initializeConfigs();
    }

    @Transactional
    public void initializePermissions() {
        createPermission(Permissions.VIEW_DASHBOARD, "Access the executive dashboard and global metrics.");
        createPermission(Permissions.VIEW_ALERTS, "View system-wide notifications and security alerts.");
        createPermission(Permissions.MANAGE_ALERTS, "Mark alerts as read or clear system notifications.");
        
        createPermission(Permissions.VIEW_ASSIGNED_PROJECTS, "See only the projects you are working on.");
        createPermission(Permissions.VIEW_ALL_PROJECTS, "See every project in the system.");
        createPermission(Permissions.ADD_PROJECT, "Create a new project record.");
        createPermission(Permissions.EDIT_ASSIGNED_PROJECTS, "Change details of projects assigned to you.");
        createPermission(Permissions.EDIT_ALL_PROJECTS, "Change details of any project in the system.");
        createPermission(Permissions.DELETE_ASSIGNED_PROJECTS, "Delete projects you are assigned to.");
        createPermission(Permissions.DELETE_ALL_PROJECTS, "Permanently remove any project record.");
        createPermission(Permissions.CHANGE_PENTEST_STATUS, "Update if a project is Active, Pending, or Completed.");
        
        createPermission(Permissions.MANAGE_REPORT_DESIGN, "Edit report logos, methodology, and disclaimers.");
        createPermission(Permissions.GENERATE_REPORT, "Create and download the final PDF/Doc report.");
        
        createPermission(Permissions.VIEW_ASSIGNED_VULNS, "Read and view vulnerability findings in assigned projects.");
        createPermission(Permissions.VIEW_ALL_VULNS, "Read and view any vulnerability finding in the system.");
        createPermission(Permissions.ADD_VULNERABILITY, "Add a new vulnerability finding to a project.");
        createPermission(Permissions.EDIT_ASSIGNED_VULNS, "Edit vulnerabilities in projects assigned to you.");
        createPermission(Permissions.EDIT_ALL_VULNS, "Edit any vulnerability in the system.");
        createPermission(Permissions.DELETE_ASSIGNED_VULNS, "Remove a vulnerability finding from an assigned project.");
        createPermission(Permissions.DELETE_ALL_VULNS, "Permanently remove any vulnerability finding.");
        createPermission(Permissions.APPROVE_ASSIGNED_VULNS, "Approve or reject findings in assigned projects.");
        createPermission(Permissions.APPROVE_ALL_VULNS, "Act as a global Approver to accept or reject findings.");
        
        createPermission(Permissions.CHANGE_VULN_REPORTING_STATUS, "Update the reporting status (e.g. Sent for Approval).");
        createPermission(Permissions.CHANGE_VULN_STATUS, "Update the technical status (e.g. Open, Fixed).");
        
        createPermission(Permissions.VIEW_USERS, "See the list of all people using the system.");
        createPermission(Permissions.MANAGE_USERS, "Create new user accounts and edit profiles.");
        createPermission(Permissions.MANAGE_ACCESS, "Configure Roles and specific User Permission keys.");
        createPermission(Permissions.MANAGE_MICROSERVICES, "Enable/Disable the external Vulnerability Database.");
        createPermission(Permissions.EDIT_MY_PROFILE, "Update your own name and profile information.");
        createPermission(Permissions.RESET_PASSWORD, "Change login passwords for yourself or others.");
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
                Permissions.VIEW_DASHBOARD, Permissions.VIEW_ALERTS, Permissions.VIEW_ASSIGNED_PROJECTS,
                Permissions.EDIT_ASSIGNED_PROJECTS, Permissions.VIEW_ASSIGNED_VULNS,
                Permissions.ADD_VULNERABILITY, Permissions.EDIT_ASSIGNED_VULNS,
                Permissions.CHANGE_VULN_STATUS, Permissions.CHANGE_VULN_REPORTING_STATUS,
                Permissions.EDIT_MY_PROFILE, Permissions.RESET_PASSWORD
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
            String pass = java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 16);
            System.out.println("\n======================================================");
            System.out.println("INITIAL ADMIN PASSWORD GENERATED: " + pass);
            System.out.println("PLEASE SAVE THIS AND CHANGE IT AFTER FIRST LOGIN.");
            System.out.println("======================================================\n");
            createUser("admin", pass, "admin@vulnprint.local", "System", "Administrator", adminRole, "Global HQ", "Root Authority");
        } else {
            // Fix for existing users: Ensure everyone is enabled and passwords are hashed
            for (User u : users) {
                boolean modified = false;
                if (!u.isEnabled()) {
                    u.setEnabled(true);
                    modified = true;
                }
                if (u.getLastRoleChange() == null) {
                    u.setLastRoleChange(java.time.LocalDateTime.now());
                    modified = true;
                }
                if (u.getPassword() != null && !u.getPassword().startsWith("$2a$") && !u.getPassword().startsWith("$2b$") && !u.getPassword().startsWith("$2y$")) {
                    u.setPassword(guard.hashPassword(u.getPassword()));
                    modified = true;
                }
                if (modified) userRepository.save(u);
            }
        }
    }

    private User createUser(String user, String pass, String email, String first, String last, Role role, String address, String qualification) {
        User u = new User();
        u.setUsername(user); 
        u.setPassword(guard.hashPassword(pass)); 
        u.setEmail(email); u.setFirstName(first); u.setLastName(last); u.setRole(role); u.setAddress(address); u.setQualification(qualification);
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
