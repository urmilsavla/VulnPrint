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
            return ResponseEntity.badRequest().body(Map.of("message", "Role already exists"));
        }
        
        Role role = new Role(name);
        return ResponseEntity.ok(roleRepository.save(role));
    }

    @PostMapping("/roles/{id}/permissions")
    @Transactional
    public ResponseEntity<?> updateRolePermissions(@PathVariable Long id, @RequestBody List<Long> permissionIds, @RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "MANAGE_ACCESS")) return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        
        return roleRepository.findById(id).map(role -> {
            Set<Permission> oldPermissions = new HashSet<>(role.getPermissions());
            Set<Permission> newPermissions = new HashSet<>(permissionRepository.findAllById(permissionIds));
            
            // Calculate removed permissions
            Set<Permission> removedPermissions = new HashSet<>(oldPermissions);
            removedPermissions.removeAll(newPermissions);
            
            role.setPermissions(newPermissions);
            roleRepository.save(role);
            
            // Sync users if permissions were removed
            if (!removedPermissions.isEmpty()) {
                List<User> usersWithRole = userRepository.findAllByRole(role);
                for (User u : usersWithRole) {
                    if (u.getExtraPermissions() != null && !u.getExtraPermissions().isEmpty()) {
                        u.getExtraPermissions().removeAll(removedPermissions);
                        userRepository.save(u);
                    }
                }
            }
            
            return ResponseEntity.ok(Map.of("message", "Role permissions updated and synchronized"));
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
        
        boolean isSelf = user.getUsername().equals(username);
        if (isSelf && !securityUtils.hasPermission(user, "EDIT_MY_PROFILE")) return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        if (!isSelf && !securityUtils.hasPermission(user, "MANAGE_USERS")) return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));

        return userRepository.findByUsername(username)
                .map(targetUser -> {
                    targetUser.setFirstName(securityUtils.encodeForHTML((String) data.get("firstName")));
                    targetUser.setLastName(securityUtils.encodeForHTML((String) data.get("lastName")));
                    targetUser.setAddress(securityUtils.encodeForHTML((String) data.get("address")));
                    targetUser.setQualification(securityUtils.encodeForHTML((String) data.get("qualification")));
                    if (data.containsKey("email")) {
                        targetUser.setEmail(securityUtils.encodeForHTML((String) data.get("email")));
                    }
                    if (data.containsKey("profileImage")) {
                        targetUser.setProfileImage((String) data.get("profileImage"));
                    }
                    
                    // Manage Role and Extra Permissions
                    if (securityUtils.hasPermission(user, "MANAGE_ACCESS")) {
                        if (data.containsKey("roleId")) {
                            roleRepository.findById(Long.valueOf(data.get("roleId").toString()))
                                .ifPresent(targetUser::setRole);
                        }
                        if (data.containsKey("extraPermissionIds")) {
                            List<Long> ids = (List<Long>) data.get("extraPermissionIds");
                            Set<Permission> extras = new HashSet<>(permissionRepository.findAllById(ids));
                            targetUser.setExtraPermissions(extras);
                        }
                    }

                    userRepository.save(targetUser);
                    return ResponseEntity.ok(Map.of("message", "Profile updated successfully"));
                }).orElse(ResponseEntity.status(404).body(Map.of("message", "User not found")));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, Object> data, @RequestAttribute("authenticatedUser") User user) {
        if (!securityUtils.hasPermission(user, "MANAGE_USERS")) {
            return ResponseEntity.status(403).body(Map.of("error", "Insufficient Permissions"));
        }

        String username = (String) data.get("username");
        if (userRepository.findByUsername(username).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Username already exists"));
        }

        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPassword(securityUtils.hashPassword((String) data.get("password")));
        newUser.setEmail((String) data.get("email"));
        newUser.setFirstName((String) data.get("firstName"));
        newUser.setLastName((String) data.get("lastName"));
        newUser.setAddress((String) data.get("address"));
        newUser.setQualification((String) data.get("qualification"));
        
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
