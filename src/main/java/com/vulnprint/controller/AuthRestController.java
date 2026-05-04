package com.vulnprint.controller;

import com.vulnprint.model.User;
import com.vulnprint.repository.UserRepository;
import com.vulnprint.service.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthRestController {

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private SecurityUtils securityUtils;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        System.out.println("Login attempt for user: " + username);

        // Fixed SQLi by using JpaRepository's parameterized query
        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isPresent()) {
            User user = userOpt.get();
            boolean matches = securityUtils.verifyPassword(password, user.getPassword());
            System.out.println("User found. Password match: " + matches);
            
            if (matches) {
                Map<String, Object> response = new HashMap<>();
                response.put("status", "success");
                response.put("token", user.getUsername()); // Simplified token for this project
                response.put("email", user.getEmail());
                response.put("firstName", user.getFirstName());
                response.put("lastName", user.getLastName());
                response.put("role", user.getRole());
                response.put("profileImage", user.getProfileImage());
                response.put("message", "Login successful");
                return ResponseEntity.ok(response);
            }
        } else {
            System.out.println("User not found: " + username);
        }

        return ResponseEntity.status(401).body(Map.of("status", "error", "message", "Invalid credentials"));
    }
}
