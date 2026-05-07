package com.vulnprint.controller;

import com.vulnprint.model.User;
import com.vulnprint.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;
import java.util.Optional;
import java.util.UUID;

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
public class UserRestController {

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
    private EmailService emailService;

    @GetMapping("/requests")
    @PreAuthorize("hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> getPendingRequests() {
        return ResponseEntity.ok(accessRequestRepository.findAll());
    }

    @PostMapping("/requests/{id}/approve")
    @Transactional
    @PreAuthorize("hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> approveRequest(@PathVariable Long id) {
        return accessRequestRepository.findById(id).map(request -> {
            request.setStatus(com.vulnprint.model.AccessRequest.RequestStatus.APPROVED);
            accessRequestRepository.save(request);
            return ResponseEntity.ok(request);
        }).orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/requests/{id}/reject")
    @PreAuthorize("hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> rejectRequest(@PathVariable Long id) {
        return accessRequestRepository.findById(id).map(request -> {
            request.setStatus(com.vulnprint.model.AccessRequest.RequestStatus.REJECTED);
            accessRequestRepository.save(request);
            // In a real system, send rejection mail here.
            return ResponseEntity.ok().build();
        }).orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/invite")
    @PreAuthorize("hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> inviteUser(@RequestBody Map<String, Object> rawData, jakarta.servlet.http.HttpServletRequest httpRequest) {
        try {
            System.out.println("[DEBUG] /api/users/invite endpoint hit with data: " + rawData);
            
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
            
            if (rawData.containsKey("roleId") && rawData.get("roleId") != null && !String.valueOf(rawData.get("roleId")).isBlank()) {
                try {
                    Long roleId = Long.valueOf(String.valueOf(rawData.get("roleId")));
                    roleRepository.findById(roleId).ifPresent(user::setRole);
                } catch (NumberFormatException nfe) {
                    System.out.println("[DEBUG] Invalid roleId format: " + rawData.get("roleId"));
                }
            }

            // Assign a secure, temporary placeholder password to satisfy any DB NOT NULL constraints.
            // The user will overwrite this when they activate their account.
            user.setPassword(guard.hashPassword(UUID.randomUUID().toString() + "Temp123!"));

            // Generate and Hash Secure Invitation Token
            String rawToken = UUID.randomUUID().toString();
            String hashedToken = org.springframework.util.DigestUtils.md5DigestAsHex(rawToken.getBytes()); 
            user.setInvitationToken(hashedToken);
            user.setInvitationExpiry(java.time.LocalDateTime.now().plusHours(24));
            
            userRepository.save(user);
            System.out.println("[DEBUG] User successfully saved to DB: " + email);

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
            System.err.println("[CRITICAL] Error in /api/users/invite: ");
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("message", "Internal Error: " + e.getMessage()));
        }
    }

    @PostMapping("/activate")
    @PreAuthorize("permitAll()")
    public ResponseEntity<?> activateAccount(@RequestBody Map<String, String> data) {
        String rawToken = data.get("token");
        String password = data.get("password");
        String hashedToken = org.springframework.util.DigestUtils.md5DigestAsHex(rawToken.getBytes());

        return userRepository.findByInvitationToken(hashedToken)
            .map(user -> {
                if (user.getInvitationExpiry().isBefore(java.time.LocalDateTime.now())) {
                    return ResponseEntity.badRequest().body(Map.of("message", "Authorization link has expired."));
                }
                
                user.setPassword(guard.hashPassword(password));
                user.setStatus(User.AccountStatus.ACTIVE);
                user.setEnabled(true);
                user.setInvitationToken(null);
                user.setInvitationExpiry(null);
                userRepository.save(user);
                
                return ResponseEntity.ok(Map.of("message", "Account activated successfully. You can now sign in."));
            }).orElse(ResponseEntity.status(404).body(Map.of("message", "Invalid authorization token.")));
    }

    @GetMapping
    @PreAuthorize("hasAuthority('VIEW_USERS')")
    public ResponseEntity<?> getAllUsers() {
        return ResponseEntity.ok(userRepository.findAll());
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
        }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/roles/{id}")
    @PreAuthorize("hasAuthority('MANAGE_ACCESS')")
    public ResponseEntity<?> deleteRole(@PathVariable Long id) {
        return roleRepository.findById(id).map(role -> {
            // Check if any users are assigned to this role
            if (!userRepository.findAllByRole(role).isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("message", "Cannot delete role as it is currently assigned to one or more users"));
            }
            roleRepository.delete(role);
            return ResponseEntity.ok().build();
        }).orElse(ResponseEntity.notFound().build());
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
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String email = (String) data.get("email");
        Long userId = data.containsKey("id") ? Long.valueOf(data.get("id").toString()) : null;
        
        Optional<User> targetOpt = userId != null ? userRepository.findById(userId) : userRepository.findByEmail(email);

        if (targetOpt.isEmpty()) return ResponseEntity.status(404).body(Map.of("message", "User not found"));
        User targetUser = targetOpt.get();

        targetUser.setFirstName(guard.sanitize((String) data.get("firstName")));
        targetUser.setLastName(guard.sanitize((String) data.get("lastName")));
        
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
        if (guard.hasPermission(user, AppSecurityGuard.MANAGE_USERS)) {
            if (data.containsKey("newPassword") && !((String) data.get("newPassword")).isEmpty()) {
                String np = (String) data.get("newPassword");
                if (!guard.isPasswordNistCompliant(np)) {
                    return ResponseEntity.badRequest().body(Map.of("message", "Password does not meet NIST entropy requirements"));
                }
                targetUser.setPassword(guard.hashPassword(np));
                securityModified = true;
            }
        }

        // Manage Role and Extra Permissions
        if (guard.hasPermission(user, AppSecurityGuard.MANAGE_ACCESS)) {

            if (data.containsKey("roleId")) {
                Long newRoleId = Long.valueOf(data.get("roleId").toString());
                if (targetUser.getRole() == null || !targetUser.getRole().getId().equals(newRoleId)) {
                    roleRepository.findById(newRoleId).ifPresent(targetUser::setRole);
                    securityModified = true;
                }
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
    }

    @PostMapping("/lockdown-reset")
    @PreAuthorize("hasAuthority('MANAGE_ACCESS')")
    public ResponseEntity<?> globalLockdown(@RequestBody Map<String, String> data) {
        try {
            guard.triggerGlobalReset(data.get("lockdownSecret"));
            return ResponseEntity.ok(Map.of("message", "Global Security Reset Initiated"));
        } catch (Exception e) {
            return ResponseEntity.status(401).body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/{id}/permissions/reset")
    @PreAuthorize("hasAuthority('MANAGE_ACCESS')")
    public ResponseEntity<?> resetPermissions(@PathVariable Long id) {
        return userRepository.findById(id).map(u -> {
            u.getExtraPermissions().clear();
            u.setLastRoleChange(java.time.LocalDateTime.now());
            userRepository.save(u);
            return ResponseEntity.ok(Map.of("message", "All permission overrides revoked and security session reset"));
        }).orElse(ResponseEntity.notFound().build());
    }

    @PatchMapping("/{id}/status")
    @PreAuthorize("hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> toggleStatus(@PathVariable Long id, @RequestBody Map<String, Boolean> data) {
        return userRepository.findById(id).map(u -> {
            if (u.getRole() != null && "Administrator".equals(u.getRole().getName())) {
                return ResponseEntity.status(403).body(Map.of("message", "Cannot suspend Administrator profile"));
            }
            u.setEnabled(data.get("enabled"));
            userRepository.save(u);
            return ResponseEntity.ok().build();
        }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (user.getId().equals(id)) return ResponseEntity.badRequest().body(Map.of("message", "Cannot delete self"));
        return userRepository.findById(id).map(target -> {
            if (target.getRole() != null && "Administrator".equals(target.getRole().getName())) {
                return ResponseEntity.status(403).body(Map.of("message", "Cannot delete Administrator profile"));
            }
            userRepository.deleteById(id);
            return ResponseEntity.ok().build();
        }).orElse(ResponseEntity.notFound().build());
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
        
        if (!isStrongPassword(password)) {
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
        
        if (data.containsKey("roleId")) {
            roleRepository.findById(Long.valueOf(data.get("roleId").toString())).ifPresent(newUser::setRole);
        } else {
            roleRepository.findByName("Penetration Tester").ifPresent(newUser::setRole);
        }
        
        User saved = userRepository.save(newUser);
        return ResponseEntity.ok(saved);
    }

    @PostMapping("/change-password")
    @PreAuthorize("#request['email'] == principal.username or hasAuthority('RESET_PASSWORD')")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> request) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String email = request.get("email");
        String currentPassword = request.get("currentPassword");
        String newPassword = request.get("newPassword");

        boolean isSelf = user.getEmail().equals(email);

        return userRepository.findByEmail(email)
            .map(targetUser -> {
                if (isSelf && !guard.verifyPassword(currentPassword, targetUser.getPassword())) {
                    return ResponseEntity.badRequest().body(Map.of("message", "Invalid current password"));
                }
                targetUser.setPassword(guard.hashPassword(newPassword));
                targetUser.setLastRoleChange(java.time.LocalDateTime.now());
                userRepository.save(targetUser);
                return ResponseEntity.ok().body(Map.of("message", "Password updated successfully and all active sessions revoked for security"));
            }).orElse(ResponseEntity.status(404).body(Map.of("message", "User not found")));
    }
}
