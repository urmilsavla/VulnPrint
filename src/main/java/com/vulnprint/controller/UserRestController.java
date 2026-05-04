package com.vulnprint.controller;

import com.vulnprint.model.User;
import com.vulnprint.repository.UserRepository;
import com.vulnprint.service.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;
import java.util.Optional;

import com.vulnprint.model.Role;
import com.vulnprint.model.Permission;
import com.vulnprint.repository.RoleRepository;
import com.vulnprint.repository.PermissionRepository;

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
    private SecurityUtils securityUtils;

    @GetMapping
    public ResponseEntity<?> getAllUsers(@RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "VIEW_USERS")) {
            return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        }
        return ResponseEntity.ok(userRepository.findAll());
    }

    @GetMapping("/roles")
    public ResponseEntity<?> getAllRoles(@RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "MANAGE_ACCESS")) return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        return ResponseEntity.ok(roleRepository.findAll());
    }

    @PostMapping("/roles")
    public ResponseEntity<?> createRole(@RequestBody Map<String, String> data, @RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "MANAGE_ACCESS")) return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        
        String name = data.get("name");
        if (roleRepository.findByName(name).isPresent()) {
            return ResponseEntity.status(409).body(Map.of("message", "A system role with this designation already exists"));
        }
        
        Role role = new Role(name);
        return ResponseEntity.ok(roleRepository.save(role));
    }

    @PostMapping("/roles/{id}/permissions")
    @Transactional
    public ResponseEntity<?> updateRolePermissions(@PathVariable Long id, @RequestBody List<Long> permissionIds, @RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "MANAGE_ACCESS")) return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        
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
            
            return ResponseEntity.ok(Map.of("message", "Role permissions updated and all active sessions revoked for security synchronization"));
        }).orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/permissions")
    public ResponseEntity<?> getAllPermissions(@RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "MANAGE_ACCESS")) return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        return ResponseEntity.ok(permissionRepository.findAll());
    }

    @GetMapping("/profile/{username}")
    public ResponseEntity<?> getProfile(@PathVariable String username, @RequestAttribute("authenticatedUser") User user) {
        if (!user.getUsername().equals(username) && !securityUtils.hasPermission(user, "VIEW_USERS")) {
            return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        }
        
        return userRepository.findByUsername(username)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.status(404).body(null));
    }

    @PostMapping("/profile")
    public ResponseEntity<?> updateProfile(@RequestBody Map<String, Object> data, @RequestAttribute("authenticatedUser") User user) {
        String username = (String) data.get("username");
        Long userId = data.containsKey("id") ? Long.valueOf(data.get("id").toString()) : null;
        
        Optional<User> targetOpt = userId != null ? userRepository.findById(userId) : userRepository.findByUsername(username);

        if (targetOpt.isEmpty()) return ResponseEntity.status(404).body(Map.of("message", "User not found"));
        User targetUser = targetOpt.get();

        boolean isSelf = user.getUsername().equals(targetUser.getUsername());
        if (isSelf && !securityUtils.hasPermission(user, "EDIT_MY_PROFILE")) return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        if (!isSelf && !securityUtils.hasPermission(user, "MANAGE_USERS")) return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));

        targetUser.setFirstName(securityUtils.encodeForHTML((String) data.get("firstName")));
        targetUser.setLastName(securityUtils.encodeForHTML((String) data.get("lastName")));
        
        if (data.containsKey("address")) targetUser.setAddress(securityUtils.encodeForHTML((String) data.get("address")));
        if (data.containsKey("qualification")) targetUser.setQualification(securityUtils.encodeForHTML((String) data.get("qualification")));
        if (data.containsKey("email")) {
            String newEmail = (String) data.get("email");
            if (newEmail != null && !newEmail.equals(targetUser.getEmail())) {
                if (userRepository.findByEmail(newEmail).isPresent()) {
                    return ResponseEntity.badRequest().body(Map.of("message", "Email already in use"));
                }
                targetUser.setEmail(securityUtils.encodeForHTML(newEmail));
            }
        }
        if (data.containsKey("profileImage")) targetUser.setProfileImage((String) data.get("profileImage"));
        
        boolean securityModified = false;

        // Admin only overrides
        if (securityUtils.hasPermission(user, "MANAGE_USERS")) {
            if (data.containsKey("newUsername")) {
                String newUsername = (String) data.get("newUsername");
                if (!newUsername.equals(targetUser.getUsername()) && userRepository.findByUsername(newUsername).isPresent()) {
                    return ResponseEntity.badRequest().body(Map.of("message", "Username already exists"));
                }
                targetUser.setUsername(newUsername);
            }
            if (data.containsKey("newPassword") && !((String) data.get("newPassword")).isEmpty()) {
                targetUser.setPassword(securityUtils.hashPassword((String) data.get("newPassword")));
                securityModified = true;
            }
        }

        // Manage Role and Extra Permissions
        if (securityUtils.hasPermission(user, "MANAGE_ACCESS")) {
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

    @PostMapping("/{id}/permissions/reset")
    public ResponseEntity<?> resetPermissions(@PathVariable Long id, @RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "MANAGE_ACCESS")) return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        
        return userRepository.findById(id).map(u -> {
            u.getExtraPermissions().clear();
            u.setLastRoleChange(java.time.LocalDateTime.now());
            userRepository.save(u);
            return ResponseEntity.ok(Map.of("message", "All permission overrides revoked and security session reset"));
        }).orElse(ResponseEntity.notFound().build());
    }

    @PatchMapping("/{id}/status")
    public ResponseEntity<?> toggleStatus(@PathVariable Long id, @RequestBody Map<String, Boolean> data, @RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "MANAGE_USERS")) return ResponseEntity.status(403).build();
        return userRepository.findById(id).map(u -> {
            u.setEnabled(data.get("enabled"));
            userRepository.save(u);
            return ResponseEntity.ok().build();
        }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id, @RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "MANAGE_USERS")) return ResponseEntity.status(403).build();
        if (user.getId().equals(id)) return ResponseEntity.badRequest().body(Map.of("message", "Cannot delete self"));
        userRepository.deleteById(id);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, Object> data, @RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "MANAGE_USERS")) {
            return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        }

        String username = (String) data.get("username");
        String password = (String) data.get("password");
        String confirmPassword = (String) data.get("confirmPassword");

        if (password == null || !password.equals(confirmPassword)) {
            return ResponseEntity.badRequest().body(Map.of("message", "Passwords do not match"));
        }

        if (userRepository.findByUsername(username).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Username already exists"));
        }

        String email = (String) data.get("email");
        if (email != null && userRepository.findByEmail(email).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Email already in use"));
        }

        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPassword(securityUtils.hashPassword(password));
        newUser.setEmail(email);
        newUser.setFirstName((String) data.get("firstName"));
        newUser.setLastName((String) data.get("lastName"));
        
        if (data.containsKey("roleId")) {
            roleRepository.findById(Long.valueOf(data.get("roleId").toString())).ifPresent(newUser::setRole);
        } else {
            roleRepository.findByName("Penetration Tester").ifPresent(newUser::setRole);
        }
        
        User saved = userRepository.save(newUser);
        return ResponseEntity.ok(saved);
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> request, @RequestAttribute("authenticatedUser") User user) {
        String username = request.get("username");
        String currentPassword = request.get("currentPassword");
        String newPassword = request.get("newPassword");

        boolean isSelf = user.getUsername().equals(username);
        if (!isSelf && !securityUtils.hasPermission(user, "RESET_PASSWORD")) return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));

        return userRepository.findByUsername(username)
            .map(targetUser -> {
                // If changing self password, must verify current password
                if (isSelf && !securityUtils.verifyPassword(currentPassword, targetUser.getPassword())) {
                    return ResponseEntity.badRequest().body(Map.of("message", "Invalid current password"));
                }
                targetUser.setPassword(securityUtils.hashPassword(newPassword));
                userRepository.save(targetUser);
                return ResponseEntity.ok().body(Map.of("message", "Password updated successfully"));
            }).orElse(ResponseEntity.status(404).body(Map.of("message", "User not found")));
    }
}
