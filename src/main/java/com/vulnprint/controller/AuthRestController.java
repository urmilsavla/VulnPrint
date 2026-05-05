package com.vulnprint.controller;

import com.vulnprint.model.User;
import com.vulnprint.repository.UserRepository;
import com.vulnprint.security.AppSecurityGuard;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Cookie;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api/auth")
public class AuthRestController {

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private AppSecurityGuard guard;

    @PostMapping("/login")
    @PreAuthorize("permitAll()")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials, HttpServletRequest request, HttpServletResponse responseObj) {
        String ip = request.getRemoteAddr();
        if (!guard.checkRateLimit(ip, "LOGIN", 5, 60000)) {
            return ResponseEntity.status(429).body(Map.of("status", "error", "message", "Too many login attempts. Please try again in a minute."));
        }

        String username = credentials.get("username");
        String password = credentials.get("password");

        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isPresent()) {
            User user = userOpt.get();
            if (guard.verifyPassword(password, user.getPassword())) {
                if (!user.isEnabled()) {
                    return ResponseEntity.status(403).body(Map.of("status", "error", "message", "Account is disabled. Please contact administrator."));
                }
                String token = guard.generateToken(user);
                
                // Set hardened HttpOnly cookie for session protection
                String cookieHeader = String.format("JWT=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict", 
                    token, 24 * 60 * 60);
                responseObj.addHeader("Set-Cookie", cookieHeader);
                
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

    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        String cookieHeader = "JWT=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict";
        response.addHeader("Set-Cookie", cookieHeader);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }
}
