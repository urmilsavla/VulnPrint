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

import com.vulnprint.service.JwtProvider;

@RestController
@RequestMapping("/api/auth")
public class AuthRestController {

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private SecurityUtils securityUtils;

    @Autowired
    private JwtProvider jwtProvider;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isPresent()) {
            User user = userOpt.get();
            if (securityUtils.verifyPassword(password, user.getPassword())) {
                if (!user.isEnabled()) {
                    return ResponseEntity.status(403).body(Map.of("status", "error", "message", "Account is disabled. Please contact administrator."));
                }
                String token = jwtProvider.generateToken(user);
                
                Map<String, Object> response = new HashMap<>();
                response.put("status", "success");
                response.put("token", token);
                response.put("username", user.getUsername());
                response.put("email", user.getEmail());
                response.put("firstName", user.getFirstName());
                response.put("lastName", user.getLastName());
                response.put("role", user.getRole() != null ? user.getRole().getName() : "None");
                response.put("profileImage", user.getProfileImage());
                response.put("message", "Login successful");
                return ResponseEntity.ok(response);
            }
        }

        return ResponseEntity.status(401).body(Map.of("status", "error", "message", "Invalid credentials"));
    }
}
