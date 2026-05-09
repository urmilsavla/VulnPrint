package com.vulnprint;

import com.vulnprint.model.User;
import com.vulnprint.model.Permission;
import com.vulnprint.model.Role;
import com.vulnprint.repository.PermissionRepository;
import com.vulnprint.repository.RoleRepository;
import com.vulnprint.repository.UserRepository;
import com.vulnprint.repository.SystemConfigRepository;
import com.vulnprint.security.AppSecurityGuard;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Component
@Order(1)
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private PermissionRepository permissionRepository;
    @Autowired
    private SystemConfigRepository systemConfigRepository;
    
    @Autowired
    private AppSecurityGuard guard;

    @Override
    public void run(String... args) throws Exception {
        try {
            initializeProductionCore();
        } catch (org.springframework.dao.InvalidDataAccessResourceUsageException e) {
            System.err.println("[CRITICAL] Database schema is incomplete or 'users' table is missing. " +
                               "Ensure hibernate.ddl-auto=update is enabled and restart the application to provision the core administrator.");
        } catch (Exception e) {
            System.err.println("[ERROR] Core initialization failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    @Transactional
    public void initializeProductionCore() {
        // 1. Initialize All System Permission Keys
        registerPermission(AppSecurityGuard.VIEW_DASHBOARD, "Access the executive dashboard and global metrics.");
        registerPermission(AppSecurityGuard.VIEW_ALERTS, "View system-wide notifications and security alerts.");
        registerPermission(AppSecurityGuard.MANAGE_ALERTS, "Mark alerts as read or clear system notifications.");
        
        registerPermission(AppSecurityGuard.VIEW_ASSIGNED_PROJECTS, "See only the projects you are working on.");
        registerPermission(AppSecurityGuard.VIEW_ALL_PROJECTS, "See every project in the system.");
        registerPermission(AppSecurityGuard.ADD_PROJECT, "Create a new project record.");
        registerPermission(AppSecurityGuard.EDIT_ASSIGNED_PROJECTS, "Change details of projects assigned to you.");
        registerPermission(AppSecurityGuard.EDIT_ALL_PROJECTS, "Change details of any project in the system.");
        registerPermission(AppSecurityGuard.DELETE_ASSIGNED_PROJECTS, "Delete projects you are assigned to.");
        registerPermission(AppSecurityGuard.DELETE_ALL_PROJECTS, "Permanently remove any project record.");
        registerPermission(AppSecurityGuard.CHANGE_PENTEST_STATUS, "Update if a project is Active, Pending, or Completed.");
        
        registerPermission(AppSecurityGuard.MANAGE_REPORT_DESIGN, "Edit report logos, methodology, and disclaimers.");
        registerPermission(AppSecurityGuard.GENERATE_REPORT, "Create and download the final PDF/Doc report.");
        
        registerPermission(AppSecurityGuard.VIEW_ASSIGNED_VULNS, "Read and view vulnerability findings in assigned projects.");
        registerPermission(AppSecurityGuard.VIEW_ALL_VULNS, "Read and view any vulnerability finding in the system.");
        registerPermission(AppSecurityGuard.ADD_VULNERABILITY, "Add a new vulnerability finding to a project.");
        registerPermission(AppSecurityGuard.EDIT_ASSIGNED_VULNS, "Edit vulnerabilities in projects assigned to you.");
        registerPermission(AppSecurityGuard.EDIT_ALL_VULNS, "Edit any vulnerability in the system.");
        registerPermission(AppSecurityGuard.DELETE_ASSIGNED_VULNS, "Remove a vulnerability finding from an assigned project.");
        registerPermission(AppSecurityGuard.DELETE_ALL_VULNS, "Permanently remove any vulnerability finding.");
        registerPermission(AppSecurityGuard.APPROVE_ASSIGNED_VULNS, "Approve or reject findings in assigned projects.");
        registerPermission(AppSecurityGuard.APPROVE_ALL_VULNS, "Act as a global Approver to accept or reject findings.");
        
        registerPermission(AppSecurityGuard.CHANGE_VULN_REPORTING_STATUS, "Update the reporting status (e.g. Sent for Approval).");
        registerPermission(AppSecurityGuard.CHANGE_VULN_STATUS, "Update the technical status (e.g. Open, Fixed).");
        
        registerPermission(AppSecurityGuard.VIEW_USERS, "See the list of all people using the system.");
        registerPermission(AppSecurityGuard.MANAGE_USERS, "Create new user accounts and edit profiles.");
        registerPermission(AppSecurityGuard.MANAGE_ACCESS, "Configure Roles and specific User Permission keys.");
        registerPermission(AppSecurityGuard.ENABLE_2FA, "Enforce Multi-Factor Authentication for the user.");
        registerPermission(AppSecurityGuard.MANAGE_MICROSERVICES, "Enable/Disable the external Vulnerability Database.");
        registerPermission(AppSecurityGuard.EDIT_MY_PROFILE, "Update your own name and profile information.");
        registerPermission(AppSecurityGuard.RESET_PASSWORD, "Change login passwords for yourself or others.");

        // 2. Initialize Administrator Role with ALL Keys
        Role adminRole = roleRepository.findByName("Administrator").orElseGet(() -> new Role("Administrator"));
        adminRole.setPermissions(new HashSet<>(permissionRepository.findAll()));
        roleRepository.save(adminRole);
        System.out.println("[PRODUCTION CORE] Administrator Role provisioned with global permissions.");

        // 3. Initialize Penetration Tester Role with Scoped Keys
        Role pentesterRole = roleRepository.findByName("Penetration Tester").orElseGet(() -> new Role("Penetration Tester"));
        Set<String> pentesterPermNames = Set.of(
            AppSecurityGuard.VIEW_DASHBOARD,
            AppSecurityGuard.VIEW_ASSIGNED_PROJECTS,
            AppSecurityGuard.ADD_PROJECT,
            AppSecurityGuard.EDIT_ASSIGNED_PROJECTS,
            AppSecurityGuard.CHANGE_PENTEST_STATUS,
            AppSecurityGuard.GENERATE_REPORT,
            AppSecurityGuard.VIEW_ASSIGNED_VULNS,
            AppSecurityGuard.ADD_VULNERABILITY,
            AppSecurityGuard.EDIT_ASSIGNED_VULNS,
            AppSecurityGuard.DELETE_ASSIGNED_VULNS,
            AppSecurityGuard.CHANGE_VULN_REPORTING_STATUS,
            AppSecurityGuard.CHANGE_VULN_STATUS,
            AppSecurityGuard.EDIT_MY_PROFILE,
            AppSecurityGuard.RESET_PASSWORD
        );
        Set<Permission> pentesterPerms = new HashSet<>(permissionRepository.findByNameIn(pentesterPermNames));
        pentesterRole.setPermissions(pentesterPerms);
        roleRepository.save(pentesterRole);
        System.out.println("[PRODUCTION CORE] Penetration Tester Role provisioned with scoped permissions.");

        // 4. Initialize Master Administrator Account
        String adminEmail = "admin@vulnprint.com";
        String adminPass = "VulPrintAdmin08$";
        
        User masterAdmin = userRepository.findByEmail(adminEmail).orElseGet(() -> {
            User u = new User();
            u.setEmail(adminEmail);
            return u;
        });

        masterAdmin.setPassword(guard.hashPassword(adminPass));
        masterAdmin.setFirstName("System");
        masterAdmin.setLastName("Administrator");
        masterAdmin.setRole(adminRole);
        masterAdmin.setEnabled(true);
        masterAdmin.setStatus(User.AccountStatus.ACTIVE);
        masterAdmin.setQualification("Lead System Architect");
        masterAdmin.setAddress(guard.encryptVault("VulnPrint Command Center"));
        
        userRepository.save(masterAdmin);
        System.out.println("[PRODUCTION CORE] Master Administrator provisioned: " + adminEmail);

        // 5. Initialize Personal Administrator Account
        String urmilEmail = "urmilsavla108@gmail.com";
        User urmil = userRepository.findByEmail(urmilEmail).orElseGet(() -> {
            User u = new User();
            u.setEmail(urmilEmail);
            return u;
        });

        urmil.setPassword(guard.hashPassword(adminPass));
        urmil.setFirstName("Urmil");
        urmil.setLastName("Savla");
        urmil.setRole(pentesterRole);
        urmil.setEnabled(true);
        urmil.setStatus(User.AccountStatus.ACTIVE);
        urmil.setQualification("M.S. in Cyber Security, OSCP, OSCE");
        urmil.setAddress(guard.encryptVault("Cyber City HQ, Terminal Tower 1"));
        
        userRepository.save(urmil);
        System.out.println("[PRODUCTION CORE] Personal Pentester account provisioned: " + urmilEmail);

        // 6. Initialize Core Configs
        if (systemConfigRepository.findAll().isEmpty()) {
            systemConfigRepository.save(new com.vulnprint.model.SystemConfig("repgen_enabled", "false"));
            systemConfigRepository.save(new com.vulnprint.model.SystemConfig("vulndb_enabled", "false"));
            systemConfigRepository.save(new com.vulnprint.model.SystemConfig("vulndb_url", ""));
            systemConfigRepository.save(new com.vulnprint.model.SystemConfig("repgen_url", ""));
        }
    }

    private void registerPermission(String name, String desc) {
        if (permissionRepository.findByName(name).isEmpty()) {
            permissionRepository.save(new Permission(name, desc));
        }
    }
}
