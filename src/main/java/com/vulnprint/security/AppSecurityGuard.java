package com.vulnprint.security;

import com.vulnprint.model.Permission;
import com.vulnprint.model.User;
import com.vulnprint.model.UserSession;
import com.vulnprint.model.Pentest;
import com.vulnprint.model.Vulnerability;
import com.vulnprint.repository.UserRepository;
import com.vulnprint.repository.UserSessionRepository;
import com.vulnprint.repository.PentestRepository;
import com.vulnprint.repository.VulnerabilityRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URL;
import java.util.concurrent.ConcurrentHashMap;
import java.util.LinkedList;
import java.util.List;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * AppSecurityGuard: The Monolithic Security Core of VulnPrint.
 * Consolidates Authentication, Sanitization, SSRF Shielding, Rate Limiting, File Integrity, Permissions, Vault Encryption, and Session Logic.
 */
@Component("guard")
public class AppSecurityGuard {

    @Autowired
    @Lazy
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserSessionRepository userSessionRepository;

    @Autowired
    private PentestRepository pentestRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private com.vulnprint.repository.AlertRepository alertRepository;

    // --- PERMISSIONS CONSTANTS ---
    // Projects (Pentests)
    public static final String VIEW_ASSIGNED_PROJECTS = "VIEW_ASSIGNED_PROJECTS";
    public static final String VIEW_ALL_PROJECTS = "VIEW_ALL_PROJECTS";
    public static final String ADD_PROJECT = "ADD_PROJECT";
    public static final String EDIT_ASSIGNED_PROJECTS = "EDIT_ASSIGNED_PROJECTS";
    public static final String EDIT_ALL_PROJECTS = "EDIT_ALL_PROJECTS";
    public static final String DELETE_ASSIGNED_PROJECTS = "DELETE_ASSIGNED_PROJECTS";
    public static final String DELETE_ALL_PROJECTS = "DELETE_ALL_PROJECTS";
    public static final String CHANGE_PENTEST_STATUS = "CHANGE_PENTEST_STATUS";

    // Vulnerabilities
    public static final String VIEW_ASSIGNED_VULNS = "VIEW_ASSIGNED_VULNS";
    public static final String VIEW_ALL_VULNS = "VIEW_ALL_VULNS";
    public static final String ADD_VULNERABILITY = "ADD_VULNERABILITY";
    public static final String EDIT_ASSIGNED_VULNS = "EDIT_ASSIGNED_VULNS";
    public static final String EDIT_ALL_VULNS = "EDIT_ALL_VULNS";
    public static final String DELETE_ASSIGNED_VULNS = "DELETE_ASSIGNED_VULNS";
    public static final String DELETE_ALL_VULNS = "DELETE_ALL_VULNS";
    public static final String APPROVE_ASSIGNED_VULNS = "APPROVE_ASSIGNED_VULNS";
    public static final String APPROVE_ALL_VULNS = "APPROVE_ALL_VULNS";
    
    // Status Modifiers
    public static final String CHANGE_VULN_REPORTING_STATUS = "CHANGE_VULN_REPORTING_STATUS";
    public static final String CHANGE_VULN_STATUS = "CHANGE_VULN_STATUS";

    // System & Design
    public static final String MANAGE_REPORT_DESIGN = "MANAGE_REPORT_DESIGN";
    public static final String GENERATE_REPORT = "GENERATE_REPORT";
    public static final String VIEW_DASHBOARD = "VIEW_DASHBOARD";
    public static final String VIEW_ALERTS = "VIEW_ALERTS";
    public static final String MANAGE_ALERTS = "MANAGE_ALERTS";
    public static final String VIEW_USERS = "VIEW_USERS";
    public static final String MANAGE_USERS = "MANAGE_USERS";
    public static final String MANAGE_ACCESS = "MANAGE_ACCESS";
    public static final String ENABLE_2FA = "ENABLE_2FA";
    public static final String MANAGE_MICROSERVICES = "MANAGE_MICROSERVICES";
    public static final String EDIT_MY_PROFILE = "EDIT_MY_PROFILE";
    public static final String RESET_PASSWORD = "RESET_PASSWORD";

    // --- CRYPTO CONSTANTS ---
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private final SecretKey vaultKey;

    // --- 1. JWT & CRYPTO PILLAR ---
    private final SecretKey jwtKey;
    private final long expirationMs = 14400000; // 4 hours for enhanced user experience
    private final Set<String> tokenBlocklist = ConcurrentHashMap.newKeySet();
    private final String jwtEnvKey;
    private final String vaultEnvKey;

    public AppSecurityGuard() {
        jwtEnvKey = System.getenv("VULNPRINT_JWT_SECRET");
        if (jwtEnvKey != null && jwtEnvKey.length() >= 32) {
            this.jwtKey = Keys.hmacShaKeyFor(jwtEnvKey.getBytes(StandardCharsets.UTF_8));
        } else {
            this.jwtKey = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS256);
        }

        vaultEnvKey = System.getenv("VULNPRINT_INTERNAL_ENC");
        if (vaultEnvKey != null && vaultEnvKey.length() >= 32) {
            this.vaultKey = new SecretKeySpec(vaultEnvKey.substring(0, 32).getBytes(StandardCharsets.UTF_8), "AES");
        } else {
            this.vaultKey = new SecretKeySpec("Fallback_Secure_Internal_Enc_Key_2026".substring(0, 32).getBytes(StandardCharsets.UTF_8), "AES");
        }
    }

    @jakarta.annotation.PostConstruct
    public void validateKeys() {
        if (jwtEnvKey == null || jwtEnvKey.length() < 32) {
            try {
                com.vulnprint.model.Alert alert = new com.vulnprint.model.Alert();
                alert.setTitle("Missing JWT Secret");
                alert.setDetails("VULNPRINT_JWT_SECRET is missing. The system is using a session-based fallback key. All active sessions will be invalidated upon system restart.");
                alert.setLevel("CRITICAL");
                alert.setTimeAgo("Just now");
                alert.setRead(false);
                alertRepository.save(alert);
            } catch(Exception e){
                System.err.println("[CRITICAL] Failed to log JWT alert to dashboard: " + e.getMessage());
            }
        }
        if (vaultEnvKey == null || vaultEnvKey.length() < 32) {
            try {
                com.vulnprint.model.Alert alert = new com.vulnprint.model.Alert();
                alert.setTitle("Missing Vault Key");
                alert.setDetails("VULNPRINT_INTERNAL_ENC is missing. Using a hardcoded internal fallback. Sensitive data encryption is NOT optimized for production.");
                alert.setLevel("CRITICAL");
                alert.setTimeAgo("Just now");
                alert.setRead(false);
                alertRepository.save(alert);
            } catch(Exception e){
                System.err.println("[CRITICAL] Failed to log Vault alert to dashboard: " + e.getMessage());
            }
        }
    }

    public void blockToken(String token) {
        if (token != null) {
            tokenBlocklist.add(token);
        }
    }

    public String generatePreAuthToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .claim("scope", "MFA_ONLY")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 120000)) // 2 minutes
                .signWith(jwtKey)
                .compact();
    }

    public String getEmailFromPreAuthToken(String token) {
        try {
            var claims = Jwts.parserBuilder().setSigningKey(jwtKey).build().parseClaimsJws(token).getBody();
            if ("MFA_ONLY".equals(claims.get("scope"))) return claims.getSubject();
            return null;
        } catch (Exception e) { return null; }
    }

    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getRole() != null ? user.getRole().getName() : "None");
        Set<String> perms = new HashSet<>();
        if (user.getRole() != null && user.getRole().getPermissions() != null) {
            perms.addAll(user.getRole().getPermissions().stream().map(Permission::getName).collect(Collectors.toSet()));
        }
        if (user.getExtraPermissions() != null) {
            perms.addAll(user.getExtraPermissions().stream().map(Permission::getName).collect(Collectors.toSet()));
        }
        claims.put("perms", perms);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getUsername())
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(jwtKey)
                .compact();
    }

    public String getEmailFromToken(String token) {
        try {
            return Jwts.parserBuilder().setSigningKey(jwtKey).build().parseClaimsJws(token).getBody().getSubject();
        } catch (Exception e) { return null; }
    }

    public String getUsernameFromToken(String token) {
        return getEmailFromToken(token);
    }

    public boolean isMfaOnlyToken(String token) {
        try {
            var claims = Jwts.parserBuilder().setSigningKey(jwtKey).build().parseClaimsJws(token).getBody();
            return "MFA_ONLY".equals(claims.get("scope"));
        } catch (Exception e) { return false; }
    }

    public Date getIssuedAtFromToken(String token) {
        try {
            return Jwts.parserBuilder().setSigningKey(jwtKey).build().parseClaimsJws(token).getBody().getIssuedAt();
        } catch (Exception e) { return null; }
    }

    public boolean validateToken(String token) {
        if (tokenBlocklist.contains(token)) return false;
        try {
            Jwts.parserBuilder().setSigningKey(jwtKey).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) { return false; }
    }

    public String hashPassword(String plaintext) {
        return plaintext == null ? null : passwordEncoder.encode(plaintext);
    }

    public boolean verifyPassword(String plaintext, String hash) {
        if (plaintext == null || hash == null) return false;
        return passwordEncoder.matches(plaintext, hash);
    }

    // --- VAULT ENCRYPTION METHODS ---
    public String encryptVault(String strToEncrypt) {
        if (strToEncrypt == null) return null;
        try {
            byte[] iv = new byte[IV_LENGTH_BYTE];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
            cipher.init(Cipher.ENCRYPT_MODE, vaultKey, spec);
            byte[] cipherText = cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8));
            
            return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(cipherText);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String decryptVault(String strToDecrypt) {
        if (strToDecrypt == null) return null;
        try {
            String[] parts = strToDecrypt.split(":");
            if (parts.length != 2) return strToDecrypt; // Not encrypted
            
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] cipherText = Base64.getDecoder().decode(parts[1]);
            
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
            cipher.init(Cipher.DECRYPT_MODE, vaultKey, spec);
            byte[] decodeText = cipher.doFinal(cipherText);
            
            return new String(decodeText, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null; 
        }
    }

    // --- SESSION LIFECYCLE METHODS ---
    @Transactional
    public Map<String, Object> establishSession(User user, String ip, String ua) {
        String refreshToken = UUID.randomUUID().toString();
        UserSession session = new UserSession();
        session.setUser(user);
        session.setRefreshTokenHash(hashPassword(refreshToken));
        session.setIpAddress(ip);
        session.setUserAgent(ua);
        session.setExpiry(LocalDateTime.now().plusDays(7));
        userSessionRepository.save(session);

        String accessToken = generateToken(user);
        
        return Map.of(
            "accessToken", accessToken,
            "refreshToken", refreshToken,
            "sessionId", session.getId().toString()
        );
    }

    @Transactional
    public void revokeAllSessionsForUser(User user) {
        userSessionRepository.findAllByUserAndRevokedFalse(user).forEach(s -> {
            s.setRevoked(true);
            userSessionRepository.save(s);
        });
    }

    @Transactional
    public Map<String, Object> rotateSession(String refreshToken, UUID sessionId, String ip, String ua) {
        UserSession oldSession = userSessionRepository.findById(sessionId).orElse(null);
        
        if (oldSession == null || oldSession.isRevoked() || !verifyPassword(refreshToken, oldSession.getRefreshTokenHash())) {
            if (oldSession != null) {
                userSessionRepository.findAllByUserAndRevokedFalse(oldSession.getUser()).forEach(s -> {
                    s.setRevoked(true);
                    userSessionRepository.save(s);
                });
            }
            throw new RuntimeException("Session Invalidated: Verification Failed");
        }

        oldSession.setRevoked(true);
        userSessionRepository.save(oldSession);

        String nextRefreshToken = UUID.randomUUID().toString();
        UserSession nextSession = new UserSession();
        nextSession.setUser(oldSession.getUser());
        nextSession.setRefreshTokenHash(hashPassword(nextRefreshToken));
        nextSession.setParentTokenId(oldSession.getId());
        nextSession.setIpAddress(ip);
        nextSession.setUserAgent(ua);
        nextSession.setExpiry(LocalDateTime.now().plusDays(7));
        userSessionRepository.save(nextSession);

        String accessToken = generateToken(oldSession.getUser());
        
        return Map.of(
            "accessToken", accessToken,
            "refreshToken", nextRefreshToken,
            "sessionId", nextSession.getId().toString()
        );
    }

    @Transactional
    public void recordFailedMfa(User user) {
        user.setFailedMfaAttempts(user.getFailedMfaAttempts() + 1);
        if (user.getFailedMfaAttempts() >= 3) {
            user.setStatus(User.AccountStatus.LOCKED);
            user.setLockedUntil(LocalDateTime.now().plusMinutes(30));
        }
        userRepository.save(user);
    }

    public boolean isStrongPassword(String password) {
        if (password == null || password.length() < 8) return false;
        boolean hasUpper = false, hasLower = false, hasNum = false;
        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isDigit(c)) hasNum = true;
        }
        return hasUpper && hasLower && hasNum;
    }

    public String hashToken(String token) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder(2 * hash.length);
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    @Transactional
    public void triggerGlobalReset(String lockdownSecret) {
        String envSecret = System.getenv("VULNPRINT_LOCKDOWN_KEY");
        if (envSecret == null || !envSecret.equals(lockdownSecret)) {
            throw new RuntimeException("Invalid Lockdown Secret");
        }
    }


    // --- 2. XSS & SANITIZATION PILLAR ---
    public String sanitize(String input) {
        if (input == null) return null;
        return HtmlUtils.htmlEscape(input.trim());
    }

    public String sanitizeProfileImage(String input) {
        if (input == null || input.isBlank()) return "/images/user.png";
        if (input.startsWith("data:image/") && input.contains(";base64,")) {
            if (input.matches("^data:image/[a-zA-Z]+;base64,[a-zA-Z0-9+/=]+$")) return input;
        }
        if (input.startsWith("/images/") && !input.contains("..") && !input.contains("%")) {
            return input;
        }
        return "/images/user.png";
    }

    // --- 3. SSRF SHIELD PILLAR ---
    public boolean isSafeUrl(String urlString) {
        return resolveSafeUrl(urlString) != null;
    }

    public String resolveSafeUrl(String urlString) {
        if (urlString == null || urlString.isBlank()) return null;

        try {
            URL url = new URL(urlString);
            String protocol = url.getProtocol().toLowerCase();
            if (!"http".equals(protocol) && !"https".equals(protocol)) return null;

            String host = url.getHost().toLowerCase();
            int port = url.getPort() != -1 ? url.getPort() : url.getDefaultPort();

            // Strict whitelist for internal services
            if ((host.equals("localhost") || host.equals("127.0.0.1")) && (port == 8000 || port == 3000)) {
                return new URL(protocol, host, port, url.getFile()).toString();
            }

            InetAddress address = InetAddress.getByName(host);
            if (address.isLoopbackAddress() || address.isAnyLocalAddress() || 
                address.isLinkLocalAddress() || address.isSiteLocalAddress()) return null;
            if ("169.254.169.254".equals(address.getHostAddress())) return null;
            
            URL safeUrl = new URL(protocol, address.getHostAddress(), port, url.getFile());
            return safeUrl.toString();
        } catch (Exception e) { return null; }
    }

    // --- 4. FILE & RCE SHIELD PILLAR ---
    public boolean isSafePath(String requestedPath, String baseDir) {
        if (requestedPath == null || baseDir == null || requestedPath.contains("\0")) return false;
        try {
            Path base = Paths.get(baseDir).toAbsolutePath().normalize();
            Path target = Paths.get(requestedPath).toAbsolutePath().normalize();
            
            // On Windows, drive letters and case can cause issues with startsWith on Strings,
            // but Path.startsWith is generally safe after absolute/normalize.
            // We use toRealPath() only if the path exists to satisfy the security mandate for resolving symlinks.
            if (java.nio.file.Files.exists(base)) base = base.toRealPath();
            if (java.nio.file.Files.exists(target)) target = target.toRealPath();
            
            return target.startsWith(base);
        } catch (IOException e) { return false; }
    }

    public String processAndSaveImage(String base64Data, String uploadDir, String fileNamePrefix) throws IOException {
        if (base64Data == null || !base64Data.contains(",")) throw new IOException("Invalid base64 image data");
        String[] parts = base64Data.split(",");
        byte[] imageBytes = Base64.getDecoder().decode(parts[1]);

        try (ByteArrayInputStream bais = new ByteArrayInputStream(imageBytes)) {
            BufferedImage image = ImageIO.read(bais);
            if (image == null) throw new IOException("Corrupted image format detected");
            
            String fileName = fileNamePrefix + "_" + UUID.randomUUID().toString() + ".png";
            File outputFile = new File(uploadDir, fileName);
            
            // Verify that the destination file will be within the project root and not traversing out
            if (!isSafePath(outputFile.getAbsolutePath(), new File(".").getAbsolutePath())) {
                throw new IOException("Security Violation: Path traversal blocked during image save");
            }
            
            if (!ImageIO.write(image, "png", outputFile)) {
                throw new IOException("Failed to write image bytes to disk");
            }
            return fileName;
        }
    }

    // --- 5. RATE LIMITING PILLAR ---
    private final Map<String, List<Long>> hits = new ConcurrentHashMap<>();

    public boolean checkRateLimit(String ip, String action, int maxRequests, long windowMs) {
        String key = ip + ":" + action;
        long now = System.currentTimeMillis();
        hits.putIfAbsent(key, Collections.synchronizedList(new LinkedList<>()));
        List<Long> timestamps = hits.get(key);

        synchronized (timestamps) {
            timestamps.removeIf(t -> now - t > windowMs);
            if (timestamps.size() >= maxRequests) return false;
            timestamps.add(now);
            return true;
        }
    }

    @org.springframework.beans.factory.annotation.Value("${vulnprint.superadmin.email:superadmin@vulnprint.com}")
    private String superAdminEmail;

    public boolean isSuperAdmin(User user) {
        return user != null && superAdminEmail.equalsIgnoreCase(user.getEmail());
    }

    public boolean hasPermission(User user, String key) {
        if (user == null || key == null) return false;
        // Super Admin has all permissions implicitly
        if (isSuperAdmin(user)) return true;
        
        if (user.getRole() != null && user.getRole().getPermissions() != null) {
            if (user.getRole().getPermissions().stream().anyMatch(p -> p.getName().equals(key))) return true;
        }
        if (user.getExtraPermissions() != null) {
            return user.getExtraPermissions().stream().anyMatch(p -> p.getName().equals(key));
        }
        return false;
    }

    // --- 6. PROJECT/VULNERABILITY CONTEXT AUTHORIZATION PILLAR ---
    private User getCurrentUser() {
        org.springframework.security.core.Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) return null;
        Object principal = auth.getPrincipal();
        if (principal instanceof User) {
            return (User) principal;
        }
        return null;
    }

    public boolean canViewProject(Long pentestId) {
        User user = getCurrentUser();
        if (user == null) return false;
        if (hasPermission(user, VIEW_ALL_PROJECTS)) return true;
        return hasPermission(user, VIEW_ASSIGNED_PROJECTS) && isAssignedToPentest(pentestId);
    }

    public boolean canEditProject(Long pentestId) {
        User user = getCurrentUser();
        if (user == null) return false;
        if (hasPermission(user, EDIT_ALL_PROJECTS)) return true;
        return hasPermission(user, EDIT_ASSIGNED_PROJECTS) && isAssignedToPentest(pentestId);
    }

    public boolean canDeleteProject(Long pentestId) {
        User user = getCurrentUser();
        if (user == null) return false;
        if (hasPermission(user, DELETE_ALL_PROJECTS)) return true;
        return hasPermission(user, DELETE_ASSIGNED_PROJECTS) && isAssignedToPentest(pentestId);
    }

    public boolean canViewVuln(Long vulnId) {
        User user = getCurrentUser();
        if (user == null) return false;
        if (hasPermission(user, VIEW_ALL_VULNS)) return true;
        return hasPermission(user, VIEW_ASSIGNED_VULNS) && isAssignedToVuln(vulnId);
    }

    public boolean canEditVuln(Long vulnId) {
        User user = getCurrentUser();
        if (user == null) return false;
        if (hasPermission(user, EDIT_ALL_VULNS)) return true;
        return hasPermission(user, EDIT_ASSIGNED_VULNS) && isAssignedToVuln(vulnId);
    }

    public boolean canDeleteVuln(Long vulnId) {
        User user = getCurrentUser();
        if (user == null) return false;
        if (hasPermission(user, DELETE_ALL_VULNS)) return true;
        return hasPermission(user, DELETE_ASSIGNED_VULNS) && isAssignedToVuln(vulnId);
    }

    public boolean canApproveVuln(Long vulnId) {
        User user = getCurrentUser();
        if (user == null) return false;
        if (hasPermission(user, APPROVE_ALL_VULNS)) return true;
        return hasPermission(user, APPROVE_ASSIGNED_VULNS) && isAssignedToVuln(vulnId);
    }

    public boolean isAssignedToPentest(Long pentestId) {
        User currentUser = getCurrentUser();
        if (currentUser == null || pentestId == null) return false;

        Optional<Pentest> pentest = pentestRepository.findById(pentestId);
        return pentest.map(p -> p.getAssignedPentesters().stream()
                .anyMatch(u -> u.getId().equals(currentUser.getId())))
                .orElse(false);
    }

    public boolean isAssignedToVuln(Long vulnId) {
        User currentUser = getCurrentUser();
        if (currentUser == null || vulnId == null) return false;

        Optional<Vulnerability> vuln = vulnerabilityRepository.findById(vulnId);
        return vuln.map(v -> v.getPentest() != null && v.getPentest().getAssignedPentesters().stream()
                .anyMatch(u -> u.getId().equals(currentUser.getId())))
                .orElse(false);
    }

    public boolean isSelf(Long userId) {
        User currentUser = getCurrentUser();
        return currentUser != null && currentUser.getId().equals(userId);
    }

    // --- MONOLITHIC NESTED COMPONENTS ---

    @Component
    public static class JwtAuthenticationFilter extends OncePerRequestFilter {
        @Autowired
        private AppSecurityGuard guard;
        @Autowired
        private UserRepository userRepository;

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {
            
            // FORCE CSRF COOKIE GENERATION FOR SPRING SECURITY 6 DEFERRED TOKENS
            org.springframework.security.web.csrf.CsrfToken csrfToken = (org.springframework.security.web.csrf.CsrfToken) request.getAttribute(org.springframework.security.web.csrf.CsrfToken.class.getName());
            if (csrfToken != null) {
                csrfToken.getToken();
            }

            String token = null;
            String authHeader = request.getHeader("Authorization");

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                token = authHeader.substring(7);
            } else if (request.getCookies() != null) {
                for (Cookie cookie : request.getCookies()) {
                    if ("JWT".equals(cookie.getName())) {
                        token = cookie.getValue();
                        break;
                    }
                }
            }

            if (token != null && guard.validateToken(token)) {
                if (guard.isMfaOnlyToken(token)) {
                    filterChain.doFilter(request, response);
                    return;
                }

                String email = guard.getEmailFromToken(token);
                final String finalToken = token;
                if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    userRepository.findActiveByEmail(email).ifPresent(user -> {
                        if (user.getStatus() != User.AccountStatus.ACTIVE || !user.isEnabled()) return;

                        Date issuedAt = guard.getIssuedAtFromToken(finalToken);
                        boolean sessionValid = true;
                        if (issuedAt != null && user.getLastRoleChange() != null) {
                            java.time.Instant lastChangeInstant = user.getLastRoleChange().atZone(java.time.ZoneId.systemDefault()).toInstant();
                            if (issuedAt.toInstant().isBefore(lastChangeInstant.minusMillis(500))) {
                                sessionValid = false;
                            }
                        }

                        if (sessionValid && user.isEnabled()) {
                            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                    user, null, user.getAuthorities());
                            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                            request.setAttribute("authenticatedUser", user);
                        }
                    });
                }
            }
            filterChain.doFilter(request, response);
        }
    }

    @Component
    public static class RateLimitingFilter extends OncePerRequestFilter {
        @Autowired
        private AppSecurityGuard guard;

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {
            
            String path = request.getRequestURI();
            String ip = request.getRemoteAddr();

            // Profile 1: Strict Limits for Auth Actions (Increased to 100 for testing)
            if (path.startsWith("/api/auth/") || path.equals("/api/users/activate")) {
                if (!guard.checkRateLimit(ip, "AUTH", 100, 60000)) {
                    response.setStatus(429);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"message\": \"Rate limit exceeded. Please try again later.\"}");
                    response.getWriter().flush();
                    return;
                }
            }
            // Profile 2: Moderate Limits for Public HTML Views (Increased to 500 for testing)
            else if (path.equals("/") || path.equals("/login") || path.equals("/activate-account") || path.equals("/error")) {
                if (!guard.checkRateLimit(ip, "VIEWS", 500, 60000)) {
                    response.setStatus(429);
                    response.setContentType("text/html");
                    response.getWriter().write("<!DOCTYPE html><html><head><title>Too Many Requests</title></head><body style='background:#0e0e0e;color:#4FFE49;font-family:monospace;text-align:center;padding:50px;'><h1>429 - Rate Limit Exceeded</h1><p>Please wait a moment before trying again.</p></body></html>");
                    response.getWriter().flush();
                    return;
                }
            }

            filterChain.doFilter(request, response);
        }
    }

    @Configuration
    @EnableWebSecurity
    @EnableMethodSecurity
    public static class SecurityConfig {
        @Autowired
        private JwtAuthenticationFilter jwtAuthenticationFilter;

        @Autowired
        private RateLimitingFilter rateLimitingFilter;

        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }

        @Bean
        public org.springframework.web.cors.CorsConfigurationSource corsConfigurationSource() {
            org.springframework.web.cors.CorsConfiguration configuration = new org.springframework.web.cors.CorsConfiguration();
            configuration.setAllowedOriginPatterns(Arrays.asList("*")); // Adjust in production to specific domains
            configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
            configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type", "X-XSRF-TOKEN"));
            configuration.setExposedHeaders(Arrays.asList("X-XSRF-TOKEN"));
            configuration.setAllowCredentials(true);
            org.springframework.web.cors.UrlBasedCorsConfigurationSource source = new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
            source.registerCorsConfiguration("/**", configuration);
            return source;
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler requestHandler = new org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler();
            requestHandler.setCsrfRequestAttributeName(null); // Opt out of deferred CSRF tokens

            http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf
                    .csrfTokenRepository(org.springframework.security.web.csrf.CookieCsrfTokenRepository.withHttpOnlyFalse())
                    .csrfTokenRequestHandler(requestHandler)
                    .ignoringRequestMatchers(
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/auth/login"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/auth/apply"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/auth/verify-mfa"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/auth/refresh"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/users/activate")
                    )
                )
                .headers(headers -> headers
                    .contentSecurityPolicy(csp -> csp
                        .policyDirectives("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://unpkg.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: blob: https:; connect-src 'self' http://localhost:* http://127.0.0.1:* ws://localhost:* ws://127.0.0.1:*; frame-ancestors 'none'; form-action 'self';")
                    )
                    .frameOptions(frame -> frame.deny())
                    .xssProtection(xss -> xss.headerValue(org.springframework.security.web.header.writers.XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                    .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                    .requestMatchers(
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/auth/login"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/auth/apply"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/auth/verify-mfa"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/auth/refresh"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/auth/reset-password"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/users/activate")
                    ).permitAll()
                    .requestMatchers(
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/css/**"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/js/**"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/images/**"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/favicon.ico")
                    ).permitAll()
                    .requestMatchers(
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/login"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/activate-account"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/reset-password"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/error")
                    ).permitAll()
                    .requestMatchers(
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/dashboard"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/web-pentest"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/mobile-pentest"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api-pentest"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/network-pentest"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/source-code-pentest"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/template-guide"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/vulnerability-approver"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/user-management"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/organization-settings"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/microservice-management"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/manage-access"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/generate-report"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/reset-password"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/profile"),
                        org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/pentest/**")
                    ).authenticated()
                    .requestMatchers(org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/**")).authenticated()
                    .anyRequest().denyAll()
                )
                .addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

            return http.build();
        }
    }
}