package com.vulnprint.controller;

import com.vulnprint.model.User;
import com.vulnprint.repository.UserRepository;
import com.vulnprint.service.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserRestController {

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private SecurityUtils securityUtils;

    @GetMapping
    public ResponseEntity<?> getAllUsers(@RequestAttribute("authenticatedUser") User user) {
        // BAC Fix: Only Administrators can list all users
        if (!"Administrator".equalsIgnoreCase(user.getRole())) {
            return ResponseEntity.status(403).body(Map.of("error", "ACCESS_DENIED: ADMINISTRATOR_CLEARANCE_REQUIRED"));
        }
        return ResponseEntity.ok(userRepository.findAll());
    }

    @GetMapping("/profile/{username}")
    public ResponseEntity<?> getProfile(@PathVariable String username, @RequestAttribute("authenticatedUser") User user) {
        // IDOR Fix: Users can only view their own profile, unless they are an Administrator
        if (!user.getUsername().equals(username) && !"Administrator".equalsIgnoreCase(user.getRole())) {
            return ResponseEntity.status(403).build();
        }
        
        return userRepository.findByUsername(username)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.status(404).body(null));
    }

    @PostMapping("/profile")
    public ResponseEntity<?> updateProfile(@RequestBody Map<String, String> data, @RequestAttribute("authenticatedUser") User user) {
        String username = data.get("username");
        
        // IDOR Fix: Users can only update their own profile, unless they are an Administrator
        if (!user.getUsername().equals(username) && !"Administrator".equalsIgnoreCase(user.getRole())) {
            return ResponseEntity.status(403).build();
        }

        return userRepository.findByUsername(username)
                .map(targetUser -> {
                    targetUser.setFirstName(securityUtils.encodeForHTML(data.get("firstName")));
                    targetUser.setLastName(securityUtils.encodeForHTML(data.get("lastName")));
                    targetUser.setAddress(securityUtils.encodeForHTML(data.get("address")));
                    targetUser.setQualification(securityUtils.encodeForHTML(data.get("qualification")));
                    if (data.containsKey("email")) {
                        targetUser.setEmail(securityUtils.encodeForHTML(data.get("email")));
                    }
                    if (data.containsKey("profileImage")) {
                        targetUser.setProfileImage(data.get("profileImage"));
                    }
                    userRepository.save(targetUser);
                    return ResponseEntity.ok(Map.of("message", "Profile updated successfully"));
                }).orElse(ResponseEntity.status(404).body(Map.of("message", "User not found")));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User newUser, @RequestAttribute("authenticatedUser") User user) {
        // BAC Fix: Only Administrators can initialize new user accounts
        if (!"Administrator".equalsIgnoreCase(user.getRole())) {
            return ResponseEntity.status(403).body(Map.of("error", "ACCESS_DENIED: ADMINISTRATOR_CLEARANCE_REQUIRED"));
        }

        if (userRepository.findByUsername(newUser.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Username already exists"));
        }
        if (newUser.getRole() == null) newUser.setRole("Pentester");
        
        // Hash the password before saving
        newUser.setPassword(securityUtils.hashPassword(newUser.getPassword()));
        
        User saved = userRepository.save(newUser);
        return ResponseEntity.ok(saved);
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> request, @RequestAttribute("authenticatedUser") User user) {
        String username = request.get("username");
        String currentPassword = request.get("currentPassword");
        String newPassword = request.get("newPassword");

        // IDOR Fix: Users can only change their own password, unless they are an Administrator
        if (!user.getUsername().equals(username) && !"Administrator".equalsIgnoreCase(user.getRole())) {
            return ResponseEntity.status(403).build();
        }

        return userRepository.findByUsername(username)
            .filter(targetUser -> securityUtils.verifyPassword(currentPassword, targetUser.getPassword()))
            .map(targetUser -> {
                targetUser.setPassword(securityUtils.hashPassword(newPassword));
                userRepository.save(targetUser);
                return ResponseEntity.ok().body(Map.of("message", "Password updated successfully"));
            }).orElse(ResponseEntity.badRequest().body(Map.of("message", "Invalid current password")));
    }
}
