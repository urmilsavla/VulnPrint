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

import com.vulnprint.model.Role;
import com.vulnprint.model.Permission;
import com.vulnprint.repository.RoleRepository;
import com.vulnprint.repository.PermissionRepository;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import com.vulnprint.security.Permissions;
import com.vulnprint.security.AppSecurityGuard;

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

    @GetMapping
    @PreAuthorize("hasAuthority('VIEW_USERS')")
    public ResponseEntity<?> getAllUsers() {
        return ResponseEntity.ok(userRepository.findAll());
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

    @GetMapping("/profile/{username}")
    @PreAuthorize("#username == principal.username or hasAuthority('VIEW_USERS')")
    public ResponseEntity<?> getProfile(@PathVariable String username) {
        return userRepository.findByUsername(username)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.status(404).body(null));
    }

    @PostMapping("/profile")
    @PreAuthorize("( #data['username'] == principal.username or ( #data['id'] != null and @securityService.isSelf(#data['id']) ) ) ? hasAuthority('EDIT_MY_PROFILE') : hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> updateProfile(@RequestBody Map<String, Object> data) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username = (String) data.get("username");
        Long userId = data.containsKey("id") ? Long.valueOf(data.get("id").toString()) : null;
        
        Optional<User> targetOpt = userId != null ? userRepository.findById(userId) : userRepository.findByUsername(username);

        if (targetOpt.isEmpty()) return ResponseEntity.status(404).body(Map.of("message", "User not found"));
        User targetUser = targetOpt.get();

        targetUser.setFirstName(guard.sanitize((String) data.get("firstName")));
        targetUser.setLastName(guard.sanitize((String) data.get("lastName")));
        
        if (data.containsKey("address")) targetUser.setAddress(guard.sanitize((String) data.get("address")));
        if (data.containsKey("qualification")) targetUser.setQualification(guard.sanitize((String) data.get("qualification")));
        if (data.containsKey("email")) {
            String newEmail = (String) data.get("email");
            if (newEmail != null && !newEmail.equals(targetUser.getEmail())) {
                if (userRepository.findByEmail(newEmail).isPresent()) {
                    return ResponseEntity.badRequest().body(Map.of("message", "Email already in use"));
                }
                targetUser.setEmail(guard.sanitize(newEmail));
            }
        }
        if (data.containsKey("profileImage")) targetUser.setProfileImage((String) data.get("profileImage"));
        
        boolean securityModified = false;



        // Admin only overrides
        if (guard.hasPermission(user, Permissions.MANAGE_USERS)) {
            if (data.containsKey("newUsername")) {
                String newUsername = (String) data.get("newUsername");
                if (!newUsername.equals(targetUser.getUsername()) && userRepository.findByUsername(newUsername).isPresent()) {
                    return ResponseEntity.badRequest().body(Map.of("message", "Username already exists"));
                }
                targetUser.setUsername(newUsername);
            }
            if (data.containsKey("newPassword") && !((String) data.get("newPassword")).isEmpty()) {
                targetUser.setPassword(guard.hashPassword((String) data.get("newPassword")));
                securityModified = true;
            }
        }

        // Manage Role and Extra Permissions
        if (guard.hasPermission(user, Permissions.MANAGE_ACCESS)) {

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
        userRepository.deleteById(id);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/register")
    @PreAuthorize("hasAuthority('MANAGE_USERS')")
    public ResponseEntity<?> register(@RequestBody Map<String, Object> data) {
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
        newUser.setPassword(guard.hashPassword(password));
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
    @PreAuthorize("#request['username'] == principal.username or hasAuthority('RESET_PASSWORD')")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> request) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username = request.get("username");
        String currentPassword = request.get("currentPassword");
        String newPassword = request.get("newPassword");

        boolean isSelf = user.getUsername().equals(username);

        return userRepository.findByUsername(username)
            .map(targetUser -> {
                // If changing self password, must verify current password
                if (isSelf && !guard.verifyPassword(currentPassword, targetUser.getPassword())) {
                    return ResponseEntity.badRequest().body(Map.of("message", "Invalid current password"));
                }
                targetUser.setPassword(guard.hashPassword(newPassword));
                userRepository.save(targetUser);
                return ResponseEntity.ok().body(Map.of("message", "Password updated successfully"));
            }).orElse(ResponseEntity.status(404).body(Map.of("message", "User not found")));
    }
}
