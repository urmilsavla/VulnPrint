package com.vulnprint.controller;

import com.vulnprint.model.User;
import com.vulnprint.repository.UserRepository;
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

    @GetMapping
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @GetMapping("/profile/{username}")
    public ResponseEntity<?> getProfile(@PathVariable String username) {
        return userRepository.findAll().stream()
                .filter(u -> u.getUsername().equals(username))
                .findFirst()
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.status(404).body(null));
    }

    @PostMapping("/profile")
    public ResponseEntity<?> updateProfile(@RequestBody Map<String, String> data) {
        String username = data.get("username");
        User user = userRepository.findAll().stream()
                .filter(u -> u.getUsername().equals(username))
                .findFirst().orElse(null);

        if (user != null) {
            user.setFirstName(data.get("firstName"));
            user.setLastName(data.get("lastName"));
            user.setAddress(data.get("address"));
            if (data.containsKey("email")) {
                user.setEmail(data.get("email"));
            }
            if (data.containsKey("profileImage")) {
                user.setProfileImage(data.get("profileImage"));
            }
            userRepository.save(user);
            return ResponseEntity.ok(Map.of("message", "Profile updated successfully"));
        }
        return ResponseEntity.status(404).body(Map.of("message", "User not found"));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Username already exists"));
        }
        if (user.getRole() == null) user.setRole("Pentester");
        User saved = userRepository.save(user);
        return ResponseEntity.ok(saved);
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String currentPassword = request.get("currentPassword");
        String newPassword = request.get("newPassword");

        return userRepository.findByUsernameAndPasswordVulnerable(username, currentPassword).stream().findFirst()
            .map(user -> {
                user.setPassword(newPassword);
                userRepository.save(user);
                return ResponseEntity.ok().body(Map.of("message", "Password updated successfully"));
            }).orElse(ResponseEntity.badRequest().body(Map.of("message", "Invalid current password")));
    }
}
