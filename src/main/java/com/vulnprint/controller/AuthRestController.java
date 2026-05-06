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

    private String dummyHash = null;

    @PostMapping("/login")
    @PreAuthorize("permitAll()")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials, HttpServletRequest request, HttpServletResponse responseObj) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        } else {
            ip = ip.split(",")[0].trim();
        }

        if (!guard.checkRateLimit(ip, "LOGIN", 5, 60000)) {
            return ResponseEntity.status(429).body(Map.of("status", "error", "message", "Too many login attempts. Please try again in a minute."));
        }

        String username = credentials.get("username");
        String password = credentials.get("password");

        if (dummyHash == null) {
            dummyHash = guard.hashPassword("dummy_initialization_string");
        }

        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isPresent()) {
            User user = userOpt.get();

            if (!user.isAccountNonLocked()) {
                return ResponseEntity.status(403).body(Map.of("status", "error", "message", "Account is locked due to too many failed attempts. Try again later."));
            }

            if (guard.verifyPassword(password, user.getPassword())) {
                if (!user.isEnabled()) {
                    return ResponseEntity.status(403).body(Map.of("status", "error", "message", "Account is disabled. Please contact administrator."));
                }

                // Reset failed attempts
                user.setFailedLoginAttempts(0);
                user.setLockedUntil(null);
                userRepository.save(user);

                String token = guard.generateToken(user);
                
                // Set hardened HttpOnly cookie for session protection
                String cookieHeader = String.format("JWT=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict", 
                    token, 15 * 60); // 15 mins matching expiration
                responseObj.addHeader("Set-Cookie", cookieHeader);
                
                Map<String, Object> response = new HashMap<>();
                response.put("status", "success");
                response.put("username", user.getUsername());
                response.put("email", user.getEmail());
                response.put("firstName", user.getFirstName());
                response.put("lastName", user.getLastName());
                response.put("role", user.getRole() != null ? user.getRole().getName() : "None");
                response.put("profileImage", user.getProfileImage());
                
                java.util.Set<String> perms = new java.util.HashSet<>();
                if (user.getRole() != null && user.getRole().getPermissions() != null) {
                    user.getRole().getPermissions().forEach(p -> perms.add(p.getName()));
                }
                if (user.getExtraPermissions() != null) {
                    user.getExtraPermissions().forEach(p -> perms.add(p.getName()));
                }
                response.put("perms", perms);
                
                response.put("message", "Login successful");
                return ResponseEntity.ok(response);
            } else {
                user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
                if (user.getFailedLoginAttempts() >= 5) {
                    user.setLockedUntil(java.time.LocalDateTime.now().plusMinutes(15));
                }
                userRepository.save(user);
            }
        } else {
            // Dummy verification to mitigate timing attacks
            guard.verifyPassword(password, dummyHash);
        }

        return ResponseEntity.status(401).body(Map.of("status", "error", "message", "Invalid credentials"));
    }

    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("JWT".equals(cookie.getName())) {
                    guard.blockToken(cookie.getValue());
                    break;
                }
            }
        }
        String cookieHeader = "JWT=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict";
        response.addHeader("Set-Cookie", cookieHeader);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }
}
