package com.vulnprint.controller;

import com.vulnprint.model.AccessRequest;
import com.vulnprint.model.User;
import com.vulnprint.repository.AccessRequestRepository;
import com.vulnprint.repository.UserRepository;
import com.vulnprint.security.AppSecurityGuard;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Cookie;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api/auth")
@org.springframework.transaction.annotation.Transactional
public class AuthRestController {

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private AccessRequestRepository accessRequestRepository;
    
    @Autowired
    private AppSecurityGuard guard;

    @Autowired
    private com.vulnprint.service.EmailService mailService;

    @Autowired
    private com.vulnprint.repository.AlertRepository alertRepository;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.security.lockout.login-duration-mins:15}")
    private int loginLockoutMins;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.security.lockout.login-max-attempts:5}")
    private int loginMaxAttempts;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.ratelimit.login.max-requests:20}")
    private int ratelimitLoginMax;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.ratelimit.login.window-ms:60000}")
    private int ratelimitLoginWindow;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.auth.mfa-otp-expiry-mins:5}")
    private int mfaOtpExpiryMins;

    private String dummyHash = null;

    @PostMapping("/apply")
    @PreAuthorize("permitAll()")
    @org.springframework.transaction.annotation.Transactional
    public ResponseEntity<?> applyForAccess(@RequestBody Map<String, String> data) {
        System.out.println("[DEBUG] Received access request for: " + data.get("email"));
        String email = data.get("email");
        if (userRepository.findByEmail(email).isPresent() || accessRequestRepository.findByEmail(email).isPresent()) {
            return ResponseEntity.status(409).body(Map.of("message", "This email is already registered or has a pending application."));
        }

        AccessRequest request = new AccessRequest();
        request.setEmail(guard.sanitize(email));
        request.setFirstName(guard.sanitize(data.get("firstName")));
        request.setLastName(guard.sanitize(data.get("lastName")));
        request.setQualification(guard.sanitize(data.get("qualification")));
        request.setReason(guard.sanitize(data.get("reason")));

        accessRequestRepository.save(request);
        return ResponseEntity.ok(Map.of("message", "Application submitted successfully"));
    }

    @PostMapping("/login")
    @PreAuthorize("permitAll()")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials, HttpServletRequest request, HttpServletResponse responseObj) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        } else {
            ip = ip.split(",")[0].trim();
        }

        if (!guard.checkRateLimit(ip, "LOGIN", ratelimitLoginMax, (long) ratelimitLoginWindow)) {
            return ResponseEntity.status(429).body(Map.of("message", "Too many login attempts. Please try again later."));
        }

        String email = credentials.get("email");
        String password = credentials.get("password");

        if (dummyHash == null) {
            dummyHash = guard.hashPassword("dummy_initialization_string");
        }

        // Pivot to Email-first lookup
        Optional<User> userOpt = userRepository.findActiveByEmail(email);

        if (userOpt.isPresent()) {
            User user = userOpt.get();

            // Auto-unlock if lockout period has expired
            if (user.getStatus() == User.AccountStatus.LOCKED && user.getLockedUntil() != null && java.time.LocalDateTime.now().isAfter(user.getLockedUntil())) {
                user.setStatus(User.AccountStatus.ACTIVE);
                user.setFailedLoginAttempts(0);
                user.setFailedMfaAttempts(0);
                user.setLockedUntil(null);
                userRepository.save(user);
            }

            if (!user.isAccountNonLocked()) {
                return ResponseEntity.status(403).body(Map.of("message", "Account is locked due to multiple failed login attempts. Please contact support."));
            }

            if (guard.verifyPassword(password, user.getPassword())) {
                if (!user.isEnabled()) {
                    return ResponseEntity.status(403).body(Map.of("message", "This account is currently disabled. Please contact the administrator."));
                }

                // Check for ENABLE_2FA Permission
                if (guard.hasPermission(user, "ENABLE_2FA")) {
                    String otp = String.format("%06d", new java.security.SecureRandom().nextInt(999999));
                    
                    // Store OTP and Expiry in User record
                    user.setMfaOtp(otp);
                    user.setMfaOtpExpiry(java.time.LocalDateTime.now().plusMinutes(mfaOtpExpiryMins));
                    userRepository.save(user);

                    // Send OTP via SMTP
                    try {
                        mailService.sendMfaOtp(user.getEmail(), otp);
                        logger.info("[SECURITY] MFA OTP TRANSMITTED TO " + email);
                        // Log OTP to console for development/testing visibility

                    } catch (Exception e) {
                        logger.error("[CRITICAL] Failed to transmit MFA OTP: " + e.getMessage(), e);
                        return ResponseEntity.status(500).body(Map.of("message", "Authentication service is temporarily unavailable. Unable to transmit verification code."));
                    }
                    
                    // Pre-Auth Token (2 mins, 0 perms)
                    String preAuth = guard.generatePreAuthToken(email);
                    
                    return ResponseEntity.status(202).body(Map.of(
                        "status", "MFA_REQUIRED",
                        "challenge", "EMAIL_OTP",
                        "preAuthToken", preAuth
                    ));
                }

                // Reset failed attempts and establish session
                user.setFailedLoginAttempts(0);
                user.setLockedUntil(null);
                userRepository.save(user);

                return establishSession(user, request, responseObj);
            } else {
                user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
                if (user.getFailedLoginAttempts() >= loginMaxAttempts) {
                    user.setLockedUntil(java.time.LocalDateTime.now().plusMinutes(loginLockoutMins));
                }
                userRepository.save(user);
            }
        } else {
            // Dummy verification to mitigate timing attacks
            guard.verifyPassword(password, dummyHash);
        }

        return ResponseEntity.status(401).body(Map.of("message", "Invalid email or password."));
    }



    private ResponseEntity<?> establishSession(User user, HttpServletRequest request, HttpServletResponse responseObj) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null) ip = request.getRemoteAddr();
        String ua = request.getHeader("User-Agent");

        Map<String, Object> session = guard.establishSession(user, ip, ua);
        
        // Access Token Cookie
        String accessCookie = String.format("JWT=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict", 
            session.get("accessToken"), 4 * 60 * 60);
        responseObj.addHeader("Set-Cookie", accessCookie);

        // Refresh Token & SessionID Cookies (Stateful)
        String refreshCookie = String.format("RT=%s; Path=/api/auth/refresh; Max-Age=%d; HttpOnly; SameSite=Strict", 
            session.get("refreshToken"), 7 * 24 * 60 * 60);
        String sidCookie = String.format("SID=%s; Path=/api/auth/refresh; Max-Age=%d; HttpOnly; SameSite=Strict", 
            session.get("sessionId"), 7 * 24 * 60 * 60);
        responseObj.addHeader("Set-Cookie", refreshCookie);
        responseObj.addHeader("Set-Cookie", sidCookie);
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("email", user.getEmail());
        response.put("firstName", user.getFirstName());
        response.put("lastName", user.getLastName());
        response.put("profileImage", user.getProfileImage());
        response.put("role", user.getRole() != null ? user.getRole().getName() : "None");
        
        java.util.Set<String> perms = new java.util.HashSet<>();
        if (user.getRole() != null && user.getRole().getPermissions() != null) {
            user.getRole().getPermissions().forEach(p -> perms.add(p.getName()));
        }
        if (user.getExtraPermissions() != null) {
            user.getExtraPermissions().forEach(p -> perms.add(p.getName()));
        }
        response.put("perms", perms);
        
        response.put("message", "Session established");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    @PreAuthorize("permitAll()")
    public ResponseEntity<?> refresh(HttpServletRequest request, HttpServletResponse responseObj) {
        String refreshToken = null;
        String sessionIdStr = null;
        
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if ("RT".equals(c.getName())) refreshToken = c.getValue();
                if ("SID".equals(c.getName())) sessionIdStr = c.getValue();
            }
        }

        if (refreshToken == null || sessionIdStr == null) return ResponseEntity.status(401).build();

        try {
            String ip = request.getHeader("X-Forwarded-For");
            if (ip == null) ip = request.getRemoteAddr();
            
            Map<String, Object> session = guard.rotateSession(refreshToken, UUID.fromString(sessionIdStr), ip, request.getHeader("User-Agent"));
            
            String accessCookie = String.format("JWT=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict", 
                session.get("accessToken"), 4 * 60 * 60);
            responseObj.addHeader("Set-Cookie", accessCookie);

            String refreshCookie = String.format("RT=%s; Path=/api/auth/refresh; Max-Age=%d; HttpOnly; SameSite=Strict", 
                session.get("refreshToken"), 7 * 24 * 60 * 60);
            String sidCookie = String.format("SID=%s; Path=/api/auth/refresh; Max-Age=%d; HttpOnly; SameSite=Strict", 
                session.get("sessionId"), 7 * 24 * 60 * 60);
            responseObj.addHeader("Set-Cookie", refreshCookie);
            responseObj.addHeader("Set-Cookie", sidCookie);

            return ResponseEntity.ok().body(Map.of("message", "Session refreshed successfully."));
        } catch (Exception e) {
            return ResponseEntity.status(401).body(Map.of("message", "Session refresh failed. Please log in again."));
        }
    }

    @PostMapping("/verify-mfa")
    @PreAuthorize("permitAll()")
    public ResponseEntity<?> verifyMfa(@RequestBody Map<String, String> data, HttpServletRequest request, HttpServletResponse responseObj) {
        String preAuthToken = data.get("preAuthToken");
        String otp = data.get("otp");

        if (preAuthToken == null || otp == null || otp.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Pre-auth token and OTP are required."));
        }

        String email = guard.getEmailFromPreAuthToken(preAuthToken);
        if (email == null) {
            return ResponseEntity.status(401).body(Map.of("message", "MFA session expired or invalid token. Please log in again."));
        }

        Optional<User> userOpt = userRepository.findActiveByEmail(email);
        if (userOpt.isPresent()) {
            User user = userOpt.get();

            // Validate OTP and Expiry with robust trimming to prevent whitespace mismatches
            if (user.getMfaOtp() != null && user.getMfaOtp().equals(otp.trim()) &&
                user.getMfaOtpExpiry() != null && user.getMfaOtpExpiry().isAfter(java.time.LocalDateTime.now())) {

                // Clear OTP after successful use
                user.setMfaOtp(null);
                user.setMfaOtpExpiry(null);
                user.setFailedMfaAttempts(0);
                user.setFailedLoginAttempts(0);
                user.setLockedUntil(null);
                userRepository.save(user);

                return establishSession(user, request, responseObj);
            } else {
                guard.recordFailedMfa(user);

                String errorMsg = "Invalid verification code.";
                if (user.getMfaOtp() == null) {
                    errorMsg = "No MFA session found for this user. Please initiate login again.";
                } else if (!user.getMfaOtp().equals(otp.trim())) {
                    errorMsg = "The verification code you entered is incorrect.";
                } else if (user.getMfaOtpExpiry() != null && user.getMfaOtpExpiry().isBefore(java.time.LocalDateTime.now())) {
                    errorMsg = "Verification code has expired.";
                }

                return ResponseEntity.status(401).body(Map.of("message", errorMsg));
            }
        }
        return ResponseEntity.status(401).body(Map.of("message", "User not found"));
    }
    @PostMapping("/reset-password")
    @PreAuthorize("permitAll()")
    @org.springframework.transaction.annotation.Transactional
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> data) {
        String rawToken = data.get("token");
        String newPassword = data.get("newPassword");
        
        if (rawToken == null || newPassword == null) {
            return ResponseEntity.badRequest().body(Map.of("message", "Token and password are required."));
        }

        String hashedToken = guard.hashToken(rawToken);

        return userRepository.findByActivationToken(hashedToken)
            .map(user -> {
                if (guard.isSuperAdmin(user)) {
                    return ResponseEntity.status(403).body(Map.of("message", "The Super Admin credentials are protected and cannot be modified via self-service."));
                }
                
                if (user.getTokenExpiry() != null && user.getTokenExpiry().isBefore(java.time.LocalDateTime.now())) {
                    return ResponseEntity.badRequest().body(Map.of("message", "The security reset link has expired. Please initiate a new request."));
                }
                
                // NIST Password Validation on Backend as well
                if (!guard.isStrongPassword(newPassword)) {
                    return ResponseEntity.badRequest().body(Map.of("message", "The provided password does not meet the organization's security requirements."));
                }

                user.setPassword(guard.hashPassword(newPassword));
                
                // SECURITY PURGE: Invalidate all existing sessions
                // 1. Update lastRoleChange to invalidate existing JWTs (JwtAuthenticationFilter checks this)
                user.setLastRoleChange(java.time.LocalDateTime.now());
                
                // 2. Revoke all active Refresh Tokens in the database
                guard.revokeAllSessionsForUser(user);
                
                // 3. Clear token to prevent reuse
                user.setActivationToken(null);
                user.setTokenExpiry(null);
                
                userRepository.save(user);

                // Audit Log
                com.vulnprint.model.Alert alert = new com.vulnprint.model.Alert();
                alert.setTitle("Credential Security Update");
                alert.setDetails("A password reset was successfully executed for User: " + user.getEmail() + ". All existing sessions have been purged.");
                alert.setLevel("System");
                alert.setTimeAgo("Just now");
                alertRepository.save(alert);
                
                return ResponseEntity.ok(Map.of("message", "Security credentials updated. All existing sessions have been revoked. Please sign in with your new credentials."));
            }).orElse(ResponseEntity.status(404).body(Map.of("message", "Invalid or expired security token.")));
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
;
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }
}


