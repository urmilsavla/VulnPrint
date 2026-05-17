package com.vulnprint.controller;

import com.vulnprint.model.User;
import com.vulnprint.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;
import java.time.LocalDateTime;

import com.vulnprint.model.Role;
import com.vulnprint.model.Permission;
import com.vulnprint.repository.RoleRepository;
import com.vulnprint.repository.PermissionRepository;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;

import com.vulnprint.security.AppSecurityGuard;
import com.vulnprint.service.EmailService;

@RestController
@RequestMapping("/api/users")
@Transactional
public class UserRestController {

    private static final Logger logger = LoggerFactory.getLogger(UserRestController.class);

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PermissionRepository permissionRepository;
    
    @Autowired
    private AppSecurityGuard guard;

    @Autowired
    private com.vulnprint.repository.AccessRequestRepository accessRequestRepository;

    @Autowired
    private com.vulnprint.repository.AlertRepository alertRepository;

    @Autowired
    private EmailService emailService;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.auth.invitation-expiry-hours:24}")
    private int invitationExpiryHours;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.auth.password-reset-expiry-mins:15}")
    private int passwordResetExpiryMins;

    @GetMapping("/requests")
    @PreAuthorize("hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> getPendingRequests() {
        return ResponseEntity.ok(accessRequestRepository.findAll());
    }

    @PostMapping("/requests/{id}/approve")
    @Transactional
    @PreAuthorize("hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> approveRequest(@PathVariable Long id) {
        return accessRequestRepository.findById(id).<ResponseEntity<?>>map(request -> {
            request.setStatus(com.vulnprint.model.AccessRequest.RequestStatus.APPROVED);
            accessRequestRepository.save(request);
            return ResponseEntity.ok(request);
        }).orElse(ResponseEntity.status(404).body(Map.of("message", "The requested resource was not found.")));
    }

    @PostMapping("/requests/{id}/reject")
    @PreAuthorize("hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> rejectRequest(@PathVariable Long id) {
        return accessRequestRepository.findById(id).map(request -> {
            request.setStatus(com.vulnprint.model.AccessRequest.RequestStatus.REJECTED);
            accessRequestRepository.save(request);
            // In a real system, send rejection mail here.
            return ResponseEntity.ok().body(Map.of("message", "User operation completed successfully."));
        }).orElse(ResponseEntity.status(404).body(Map.of("message", "The requested resource was not found.")));
    }

    @PostMapping("/invite")
    @PreAuthorize("hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> inviteUser(@RequestBody Map<String, Object> rawData, jakarta.servlet.http.HttpServletRequest httpRequest) {
        try {
            // logger.debug("/api/users/invite endpoint hit with data: " + rawData);
            
            String rawEmail = rawData.get("email") != null ? String.valueOf(rawData.get("email")) : "";
            String email = guard.sanitize(rawEmail);
            
            if (email == null || email.isBlank()) {
                return ResponseEntity.badRequest().body(Map.of("message", "Email is required."));
            }
            
            if (userRepository.findByEmail(email).isPresent()) {
                return ResponseEntity.badRequest().body(Map.of("message", "User already exists with this identity."));
            }

            User user = new User();
            user.setEmail(email);
            
            String firstName = rawData.get("firstName") != null ? String.valueOf(rawData.get("firstName")) : "";
            String lastName = rawData.get("lastName") != null ? String.valueOf(rawData.get("lastName")) : "";
            
            user.setFirstName(guard.sanitize(firstName));
            user.setLastName(guard.sanitize(lastName));
            user.setStatus(User.AccountStatus.INVITED);
            user.setEnabled(false); 
            
            if (rawData.containsKey("qualification")) {
                user.setQualification(guard.sanitize((String) rawData.get("qualification")));
            }
            if (rawData.containsKey("address")) {
                user.setAddress(guard.encryptVault(guard.sanitize((String) rawData.get("address"))));
            }
            
            if (rawData.containsKey("roleId") && rawData.get("roleId") != null && !String.valueOf(rawData.get("roleId")).isBlank()) {
                try {
                    Long roleId = Long.valueOf(String.valueOf(rawData.get("roleId")));
                    roleRepository.findById(roleId).ifPresent(user::setRole);
                } catch (NumberFormatException nfe) {
                    // logger.debug("Invalid roleId format: " + rawData.get("roleId"));
                }
            }

            // Assign a secure, temporary placeholder password to satisfy any DB NOT NULL constraints.
            // The user will overwrite this when they activate their account.
            user.setPassword(guard.hashPassword(UUID.randomUUID().toString() + "Temp123!"));

            // Generate and Hash Secure Invitation Token
            String rawToken = UUID.randomUUID().toString();
            String hashedToken = guard.hashToken(rawToken); 
            user.setInvitationToken(hashedToken);
            user.setInvitationExpiry(java.time.LocalDateTime.now().plusHours(invitationExpiryHours));
            
            userRepository.save(user);
            logger.info("[DEBUG] User successfully saved to DB: " + email);

            // Construct full activation URL based on the request's origin
            String baseUrl = String.format("%s://%s:%d", httpRequest.getScheme(), httpRequest.getServerName(), httpRequest.getServerPort());
            String authLink = "/activate-account?token=" + rawToken;
            String fullAuthLink = baseUrl + authLink;
            
            // Send Invitation Email
            emailService.sendInvitationEmail(email, user.getFirstName(), fullAuthLink);

            return ResponseEntity.ok(Map.of(
                "message", "Authorization link generated successfully and email sent.",
                "authLink", authLink
            ));
        } catch (Exception e) {
            logger.error("[CRITICAL] Error in /api/users/invite: ", e);
            logger.error("Exception occurred: ", e);
            return ResponseEntity.status(500).body(Map.of("message", "Unable to process the invitation request at this time. Please contact support."));
        }
    }


    @PostMapping("/activate")
    @PreAuthorize("permitAll()")
    public ResponseEntity<?> activateAccount(@RequestBody Map<String, String> data) {
        String rawToken = data.get("token");
        String password = data.get("password");
        String hashedToken = guard.hashToken(rawToken);

        Optional<User> userOpt = userRepository.findByInvitationToken(hashedToken);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(404).body(Map.of("message", "Invalid authorization token."));
        }

        User user = userOpt.get();
        if (user.getInvitationExpiry() != null && user.getInvitationExpiry().isBefore(java.time.LocalDateTime.now())) {
            return ResponseEntity.badRequest().body(Map.of("message", "Authorization link has expired."));
        }
        
        // Security: Revoke all existing sessions if this is a reset for an active user
        if (user.getStatus() == User.AccountStatus.ACTIVE) {
            user.setLastRoleChange(java.time.LocalDateTime.now());
        }

        user.setPassword(guard.hashPassword(password));
        user.setStatus(User.AccountStatus.ACTIVE);
        user.setEnabled(true);
        user.setInvitationToken(null);
        user.setInvitationExpiry(null);
        
        userRepository.saveAndFlush(user);
        
        return ResponseEntity.ok(Map.of("message", "Account activated successfully. You can now sign in."));
    }

    @GetMapping
    @PreAuthorize("hasAuthority('VIEW_USERS') or hasAuthority('ADD_PROJECT') or hasAuthority('EDIT_ALL_PROJECTS') or hasAuthority('EDIT_ASSIGNED_PROJECTS')")
    public ResponseEntity<?> getAllUsers(@RequestParam(required = false, defaultValue = "false") boolean includeDeleted) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        boolean hasFullView = guard.hasPermission(currentUser, "VIEW_USERS") || guard.isSuperAdmin(currentUser);

        List<User> users = userRepository.findAll().stream()
                .filter(u -> includeDeleted || !u.isDeleted())
                .collect(Collectors.toList());
        
        if (hasFullView) {
            users.forEach(u -> {
                if (u.getAddress() != null && !u.getAddress().isEmpty()) {
                    try {
                        u.setAddress(guard.decryptVault(u.getAddress()));
                    } catch (Exception e) {
                        // Log but continue
                    }
                }
            });
            return ResponseEntity.ok(users);
        } else {
            // Sanitize: Return only non-sensitive data for assignment purposes
            return ResponseEntity.ok(users.stream().map(u -> {
                Map<String, Object> map = new HashMap<>();
                map.put("id", u.getId());
                map.put("firstName", u.getFirstName());
                map.put("lastName", u.getLastName());
                map.put("email", u.getEmail());
                map.put("role", u.getRole());
                map.put("profileImage", u.getProfileImage());
                return map;
            }).collect(Collectors.toList()));
        }
    }

    @GetMapping("/check-email")
    @PreAuthorize("hasAuthority('VIEW_USERS') or hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> checkEmail(@RequestParam String email) {
        return ResponseEntity.ok(Map.of("exists", userRepository.findByEmail(email).isPresent()));
    }

    @GetMapping("/roles")
    @PreAuthorize("hasAuthority('MANAGE_ACCESS')")
    public ResponseEntity<?> getAllRoles() {
        return ResponseEntity.ok(roleRepository.findAll());
    }

    @PostMapping("/roles")
    @PreAuthorize("hasAuthority('MANAGE_ACCESS')")
    public ResponseEntity<?> createRole(@RequestBody Map<String, String> data) {
        String name = guard.sanitize(data.get("name"));
        if (roleRepository.findByName(name).isPresent()) {
            return ResponseEntity.status(409).body(Map.of("message", "A system role with this designation already exists"));
        }
        
        Role role = new Role(name);
        return ResponseEntity.ok(roleRepository.save(role));
    }

    @PostMapping("/roles/{id}/permissions")
    @Transactional
    @PreAuthorize("hasAuthority('MANAGE_ACCESS')")
    public ResponseEntity<?> updateRolePermissions(@PathVariable Long id, @RequestBody List<Long> permissionIds) {
        return roleRepository.findById(id).map(role -> {
            if ("Super Admin".equals(role.getName())) {
                return ResponseEntity.status(403).body(Map.of("message", "The Super Admin role is immutable and cannot be modified."));
            }
            Set<Permission> newPermissions = new HashSet<>(permissionRepository.findAllById(permissionIds));
            role.setPermissions(newPermissions);
            roleRepository.save(role);
            
            // Invalidate all tokens for users with this role
            List<User> usersWithRole = userRepository.findAllByRole(role);
            for (User u : usersWithRole) {
                u.setLastRoleChange(java.time.LocalDateTime.now());
                userRepository.save(u);
            }
            
            return ResponseEntity.ok(Map.of("message", "Role permissions updated and all active sessions revoked for security update"));
        }).orElse(ResponseEntity.status(404).body(Map.of("message", "The requested resource was not found.")));
    }

    @DeleteMapping("/roles/{id}")
    @PreAuthorize("hasAuthority('MANAGE_ACCESS')")
    public ResponseEntity<?> deleteRole(@PathVariable Long id) {
        return roleRepository.findById(id).map(role -> {
            if ("Super Admin".equals(role.getName())) {
                return ResponseEntity.status(403).body(Map.of("message", "The Super Admin role is a core system component and cannot be removed."));
            }
            // Check if any users are assigned to this role
            if (!userRepository.findAllByRole(role).isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("message", "Cannot delete role as it is currently assigned to one or more users"));
            }
            roleRepository.delete(role);
            return ResponseEntity.ok().body(Map.of("message", "User operation completed successfully."));
        }).orElse(ResponseEntity.status(404).body(Map.of("message", "The requested resource was not found.")));
    }

    @GetMapping("/permissions")
    @PreAuthorize("hasAuthority('MANAGE_ACCESS')")
    public ResponseEntity<?> getAllPermissions() {
        return ResponseEntity.ok(permissionRepository.findAll());
    }

    @GetMapping("/profile/{email}")
    @PreAuthorize("#email == principal.username or hasAuthority('VIEW_USERS')")
    public ResponseEntity<?> getProfile(@PathVariable String email) {
        return userRepository.findActiveByEmail(email)
                .map(user -> {
                    // Decrypt Vault data for frontend display
                    if (user.getAddress() != null && !user.getAddress().isEmpty()) {
                        try {
                            user.setAddress(guard.decryptVault(user.getAddress()));
                        } catch (Exception e) {
                            System.err.println("Decryption failed for user address: " + e.getMessage());
                        }
                    }
                    return ResponseEntity.ok(user);
                })
                .orElse(ResponseEntity.status(404).body(null));
    }



    @PostMapping("/profile")
    @PreAuthorize("hasAuthority('MANAGE_USERS') or (hasAuthority('EDIT_MY_PROFILE') and ( #data['email'] == principal.username or ( #data['id'] != null and @guard.isSelf(#data['id']) ) ))")
    public ResponseEntity<?> updateProfile(@RequestBody Map<String, Object> data) {
        try {
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            String email = (String) data.get("email");
            Long userId = null;
            if (data.containsKey("id") && data.get("id") != null && !data.get("id").toString().isEmpty()) {
                userId = Long.valueOf(data.get("id").toString());
            }
            
            Optional<User> targetOpt = userId != null ? userRepository.findById(userId) : userRepository.findByEmail(email);

            if (targetOpt.isEmpty()) return ResponseEntity.status(404).body(Map.of("message", "User not found"));
            User targetUser = targetOpt.get();

            if (guard.isSuperAdmin(targetUser)) {
                return ResponseEntity.status(403).body(Map.of("message", "The Super Admin profile is immutable and protected by core system logic."));
            }

            if (data.containsKey("firstName")) targetUser.setFirstName(guard.sanitize((String) data.get("firstName")));
            if (data.containsKey("lastName")) targetUser.setLastName(guard.sanitize((String) data.get("lastName")));
            
            // PII Vault Encryption for Address
            if (data.containsKey("address")) {
                String rawAddress = (String) data.get("address");
                targetUser.setAddress(guard.encryptVault(guard.sanitize(rawAddress)));
            }
            
            if (data.containsKey("qualification")) {
                targetUser.setQualification(guard.sanitize((String) data.get("qualification")));
            }

            if (data.containsKey("profileImage")) {
                targetUser.setProfileImage(guard.sanitizeProfileImage((String) data.get("profileImage")));
            }
            
            if (data.containsKey("email")) {
                String newEmail = (String) data.get("email");
                if (newEmail != null && !newEmail.equals(targetUser.getEmail())) {
                    if (userRepository.findByEmail(newEmail).isPresent()) {
                        return ResponseEntity.badRequest().body(Map.of("message", "Email already in use"));
                    }
                    targetUser.setEmail(guard.sanitize(newEmail));
                }
            }
            
            boolean securityModified = false;

            // Admin only overrides
            if (guard.hasPermission(currentUser, AppSecurityGuard.MANAGE_USERS)) {
                if (data.containsKey("newPassword") && data.get("newPassword") != null && !data.get("newPassword").toString().isEmpty()) {
                    String np = (String) data.get("newPassword");
                    if (!guard.isStrongPassword(np)) {
                        return ResponseEntity.badRequest().body(Map.of("message", "The provided password does not meet the organization's security requirements."));
                    }
                    targetUser.setPassword(guard.hashPassword(np));
                    securityModified = true;
                }
            }

            // Manage Role and Extra Permissions
            if (guard.hasPermission(currentUser, AppSecurityGuard.MANAGE_ACCESS)) {
                if (data.containsKey("roleId") && data.get("roleId") != null && !data.get("roleId").toString().isEmpty()) {
                    try {
                        Long newRoleId = Long.valueOf(data.get("roleId").toString());
                        if (targetUser.getRole() == null || !targetUser.getRole().getId().equals(newRoleId)) {
                            roleRepository.findById(newRoleId).ifPresent(targetUser::setRole);
                            securityModified = true;
                        }
                    } catch (NumberFormatException nfe) {}
                }
                if (data.containsKey("extraPermissionIds")) {
                    List<Long> ids = (List<Long>) data.get("extraPermissionIds");
                    Set<Permission> extras = new HashSet<>(permissionRepository.findAllById(ids));
                    targetUser.setExtraPermissions(extras);
                    securityModified = true;
                }
            }

            if (securityModified) {
                targetUser.setLastRoleChange(java.time.LocalDateTime.now());
            }

            userRepository.save(targetUser);
            return ResponseEntity.ok(Map.of("message", "Profile updated successfully" + (securityModified ? " and security sessions revoked" : "")));
        } catch (Exception e) {
            logger.error("Exception occurred: ", e);
            return ResponseEntity.status(400).body(Map.of("message", "Unable to update profile. Please ensure all data is correctly formatted."));
        }
    }

    @PostMapping("/lockdown-reset")
    @PreAuthorize("hasAuthority('MANAGE_ACCESS')")
    public ResponseEntity<?> globalLockdown(@RequestBody Map<String, String> data) {
        try {
            guard.triggerGlobalReset(data.get("lockdownSecret"));
            return ResponseEntity.ok(Map.of("message", "Global Security Reset Initiated"));
        } catch (Exception e) {
            return ResponseEntity.status(401).body(Map.of("message", "Global Security Reset failed. Please verify credentials."));
        }
    }

    @PostMapping("/{id}/permissions/reset")
    @PreAuthorize("hasAuthority('MANAGE_ACCESS')")
    public ResponseEntity<?> resetPermissions(@PathVariable Long id) {
        return userRepository.findById(id).map(u -> {
            if (guard.isSuperAdmin(u)) {
                return ResponseEntity.status(403).body(Map.of("message", "The Super Admin profile is immutable and protected by core system logic."));
            }
            u.getExtraPermissions().clear();
            u.setLastRoleChange(java.time.LocalDateTime.now());
            userRepository.save(u);
            return ResponseEntity.ok(Map.of("message", "All permission overrides revoked and security session reset"));
        }).orElse(ResponseEntity.status(404).body(Map.of("message", "The requested resource was not found.")));
    }

    @PatchMapping("/{id}/status")
    @PreAuthorize("hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> toggleStatus(@PathVariable Long id, @RequestBody Map<String, Boolean> data) {
        return userRepository.findById(id).map(u -> {
            if (guard.isSuperAdmin(u)) {
                return ResponseEntity.status(403).body(Map.of("message", "The Super Admin profile is immutable and protected by core system logic."));
            }
            u.setEnabled(data.get("enabled"));
            userRepository.save(u);
            return ResponseEntity.ok().body(Map.of("message", "User operation completed successfully."));
        }).orElse(ResponseEntity.status(404).body(Map.of("message", "The requested resource was not found.")));
    }

    @PostMapping("/me/trigger-reset")
    @PreAuthorize("hasAuthority('EDIT_MY_PROFILE')")
    public ResponseEntity<?> triggerSelfReset(jakarta.servlet.http.HttpServletRequest httpRequest) {
        org.springframework.security.core.Authentication auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) return ResponseEntity.status(401).body(Map.of("message", "Authentication required"));
        
        User target = (User) auth.getPrincipal();
        if (guard.isSuperAdmin(target)) {
            return ResponseEntity.status(403).body(Map.of("message", "The Super Admin credentials are protected and cannot be modified via self-service."));
        }
        try {
            String rawToken = UUID.randomUUID().toString();
            String hashedToken = guard.hashToken(rawToken);

            target.setActivationToken(hashedToken);
            target.setTokenExpiry(LocalDateTime.now().plusMinutes(passwordResetExpiryMins));
            userRepository.save(target);

            com.vulnprint.model.Alert alert = new com.vulnprint.model.Alert();
            alert.setTitle("Self-Reset Triggered");
            alert.setDetails("User " + target.getFirstName() + " " + target.getLastName() + " initiated a personal password reset.");
            alert.setLevel("System");
            alert.setTimeAgo("Just now");
            alertRepository.save(alert);

            String baseUrl = httpRequest.getScheme() + "://" + httpRequest.getServerName() + (httpRequest.getServerPort() != 80 && httpRequest.getServerPort() != 443 ? ":" + httpRequest.getServerPort() : "");
            String resetLink = baseUrl + "/reset-password?token=" + rawToken;

            emailService.sendPasswordResetEmail(target.getEmail(), target.getFirstName(), resetLink);

            return ResponseEntity.ok().body(Map.of("message", "Security reset link transmitted to your registered email."));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("message", "Failed to process security reset request."));
        }
    }

    @PostMapping("/{id}/trigger-reset")
    @PreAuthorize("hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> triggerReset(@PathVariable Long id, jakarta.servlet.http.HttpServletRequest httpRequest) {
        User admin = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return userRepository.findById(id).map(target -> {
            if (guard.isSuperAdmin(target)) {
                return ResponseEntity.status(403).body(Map.of("message", "The Super Admin credentials are protected and cannot be modified via self-service."));
            }
            
            String rawToken = UUID.randomUUID().toString();
            String hashedToken = guard.hashToken(rawToken);
            
            target.setActivationToken(hashedToken);
            target.setTokenExpiry(java.time.LocalDateTime.now().plusMinutes(passwordResetExpiryMins));
            userRepository.save(target);

            // Audit Log
            com.vulnprint.model.Alert alert = new com.vulnprint.model.Alert();
            alert.setTitle("Password Reset Triggered");
            alert.setDetails("Admin " + admin.getFirstName() + " " + admin.getLastName() + " initiated a password reset for User " + target.getFirstName() + " " + target.getLastName());
            alert.setLevel("System");
            alert.setTimeAgo("Just now");
            alertRepository.save(alert);
            
            String baseUrl = String.format("%s://%s:%d", httpRequest.getScheme(), httpRequest.getServerName(), httpRequest.getServerPort());
            String resetLink = baseUrl + "/reset-password?token=" + rawToken;
            
            emailService.sendPasswordResetEmail(target.getEmail(), target.getFirstName(), resetLink);

            return ResponseEntity.ok().body(Map.of("message", "Password reset link transmitted successfully."));
        }).orElse(ResponseEntity.status(404).body(Map.of("message", "User not found.")));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (user.getId().equals(id)) return ResponseEntity.badRequest().body(Map.of("message", "Cannot delete self"));
        return userRepository.findById(id).map(target -> {
            if (guard.isSuperAdmin(target)) {
                return ResponseEntity.status(403).body(Map.of("message", "The Super Admin profile is immutable and protected by core system logic."));
            }
            try {
                target.setDeleted(true);
                target.setEnabled(false);
                target.setStatus(User.AccountStatus.DELETED);
                
                // Avoid UNIQUE constraint conflicts for future registrations
                String timestamp = String.valueOf(System.currentTimeMillis());
                target.setEmail(target.getEmail() + "_DELETED_" + timestamp);
                
                userRepository.save(target);
                
                return ResponseEntity.ok().body(Map.of("message", "User operation completed successfully."));
            } catch (Exception e) {
                return ResponseEntity.status(500).body(Map.of("message", "An internal system error occurred during the delete operation."));
            }
        }).orElse(ResponseEntity.status(404).body(Map.of("message", "The requested resource was not found.")));
    }

    @PostMapping("/register")
    @PreAuthorize("hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> register(@RequestBody Map<String, Object> data) {
        String email = (String) data.get("email");
        String password = (String) data.get("password");
        String confirmPassword = (String) data.get("confirmPassword");

        if (password == null || !password.equals(confirmPassword)) {
            return ResponseEntity.badRequest().body(Map.of("message", "Passwords do not match"));
        }
        
        if (!guard.isStrongPassword(password)) {
            return ResponseEntity.badRequest().body(Map.of("message", "Password does not meet security requirements."));
        }

        if (userRepository.findByEmail(email).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("message", "This email ID is already registered."));
        }

        User newUser = new User();
        newUser.setEmail(guard.sanitize(email));
        newUser.setPassword(guard.hashPassword(password));
        newUser.setFirstName(guard.sanitize((String) data.get("firstName")));
        newUser.setLastName(guard.sanitize((String) data.get("lastName")));
        
        if (data.containsKey("qualification")) {
            newUser.setQualification(guard.sanitize((String) data.get("qualification")));
        }
        if (data.containsKey("address")) {
            newUser.setAddress(guard.encryptVault(guard.sanitize((String) data.get("address"))));
        }
        
        if (data.containsKey("roleId")) {
            roleRepository.findById(Long.valueOf(data.get("roleId").toString())).ifPresent(newUser::setRole);
        } else {
            roleRepository.findByName("Penetration Tester").ifPresent(newUser::setRole);
        }
        
        User saved = userRepository.save(newUser);
        return ResponseEntity.ok(saved);
    }
}
