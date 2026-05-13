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
    public static final String VIEW_ASSIGNED_PROJECTS = "VIEW_ASSIGNED_PROJECTS";
    public static final String VIEW_ALL_PROJECTS = "VIEW_ALL_PROJECTS";
    public static final String ADD_PROJECT = "ADD_PROJECT";
    public static final String EDIT_ASSIGNED_PROJECTS = "EDIT_ASSIGNED_PROJECTS";
    public static final String EDIT_ALL_PROJECTS = "EDIT_ALL_PROJECTS";
    public static final String DELETE_ASSIGNED_PROJECTS = "DELETE_ASSIGNED_PROJECTS";
    public static final String DELETE_ALL_PROJECTS = "DELETE_ALL_PROJECTS";
    public static final String CHANGE_PENTEST_STATUS = "CHANGE_PENTEST_STATUS";
    public static final String VIEW_ASSIGNED_VULNS = "VIEW_ASSIGNED_VULNS";
    public static final String VIEW_ALL_VULNS = "VIEW_ALL_VULNS";
    public static final String ADD_VULNERABILITY = "ADD_VULNERABILITY";
    public static final String EDIT_ASSIGNED_VULNS = "EDIT_ASSIGNED_VULNS";
    public static final String EDIT_ALL_VULNS = "EDIT_ALL_VULNS";
    public static final String DELETE_ASSIGNED_VULNS = "DELETE_ASSIGNED_VULNS";
    public static final String DELETE_ALL_VULNS = "DELETE_ALL_VULNS";
    public static final String APPROVE_ASSIGNED_VULNS = "APPROVE_ASSIGNED_VULNS";
    public static final String APPROVE_ALL_VULNS = "APPROVE_ALL_VULNS";
    public static final String CHANGE_VULN_REPORTING_STATUS = "CHANGE_VULN_REPORTING_STATUS";
    public static final String CHANGE_VULN_STATUS = "CHANGE_VULN_STATUS";
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
    private SecretKey vaultKey;
    private SecretKey jwtKey;
    
    @org.springframework.beans.factory.annotation.Value("${vulnprint.security.jwt-expiration-ms:14400000}")
    private long expirationMs;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.security.pre-auth-expiry-ms:120000}")
    private long preAuthExpirationMs;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.security.session-expiry-days:7}")
    private int sessionExpiryDays;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.security.password.min-length:8}")
    private int minPasswordLength;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.security.token-invalidation-buffer-ms:500}")
    private int tokenInvalidationBufferMs;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.security.lockout.mfa-duration-mins:30}")
    private int mfaLockoutMins;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.security.lockout.mfa-max-attempts:3}")
    private int mfaMaxAttempts;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.ratelimit.auth.max-requests:100}")
    private int ratelimitAuthMax;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.ratelimit.auth.window-ms:60000}")
    private int ratelimitAuthWindow;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.ratelimit.views.max-requests:500}")
    private int ratelimitViewsMax;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.ratelimit.views.window-ms:60000}")
    private int ratelimitViewsWindow;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.ui.assets.default-user-image:/images/user.png}")
    private String defaultUserImage;

    private final Set<String> tokenBlocklist = ConcurrentHashMap.newKeySet();

    @org.springframework.beans.factory.annotation.Value("${vulnprint.security.jwt-secret}")
    private String jwtSecret;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.security.vault-key}")
    private String vaultSecret;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.security.lockdown-key}")
    private String lockdownSecretKey;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.security.ssrf.allowed-hosts}")
    private List<String> allowedHosts;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.security.ssrf.allowed-ports}")
    private List<Integer> allowedPorts;

    @jakarta.annotation.PostConstruct
    public void init() {
        if (jwtSecret != null && jwtSecret.length() >= 32) {
            this.jwtKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        } else {
            this.jwtKey = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS256);
        }
        if (vaultSecret != null && vaultSecret.length() >= 32) {
            this.vaultKey = new SecretKeySpec(vaultSecret.substring(0, 32).getBytes(StandardCharsets.UTF_8), "AES");
        } else {
            this.vaultKey = new SecretKeySpec("Fallback_Secure_Internal_Enc_Key_2026".substring(0, 32).getBytes(StandardCharsets.UTF_8), "AES");
        }
    }

    public void blockToken(String token) { if (token != null) tokenBlocklist.add(token); }

    public String generatePreAuthToken(String email) {
        return Jwts.builder().setSubject(email).claim("scope", "MFA_ONLY").setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + preAuthExpirationMs)).signWith(jwtKey).compact();
    }

    public String getEmailFromPreAuthToken(String token) {
        try {
            var claims = Jwts.parserBuilder().setSigningKey(jwtKey).build().parseClaimsJws(token).getBody();
            return "MFA_ONLY".equals(claims.get("scope")) ? claims.getSubject() : null;
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
        return Jwts.builder().setClaims(claims).setSubject(user.getUsername()).setId(UUID.randomUUID().toString())
                .setIssuedAt(new Date()).setExpiration(new Date(System.currentTimeMillis() + expirationMs)).signWith(jwtKey).compact();
    }

    public String getEmailFromToken(String token) {
        try { return Jwts.parserBuilder().setSigningKey(jwtKey).build().parseClaimsJws(token).getBody().getSubject(); }
        catch (Exception e) { return null; }
    }

    public boolean isMfaOnlyToken(String token) {
        try { return "MFA_ONLY".equals(Jwts.parserBuilder().setSigningKey(jwtKey).build().parseClaimsJws(token).getBody().get("scope")); }
        catch (Exception e) { return false; }
    }

    public Date getIssuedAtFromToken(String token) {
        try { return Jwts.parserBuilder().setSigningKey(jwtKey).build().parseClaimsJws(token).getBody().getIssuedAt(); }
        catch (Exception e) { return null; }
    }

    public boolean validateToken(String token) {
        if (tokenBlocklist.contains(token)) return false;
        try { Jwts.parserBuilder().setSigningKey(jwtKey).build().parseClaimsJws(token); return true; }
        catch (Exception e) { return false; }
    }

    public String hashPassword(String p) { return p == null ? null : passwordEncoder.encode(p); }
    public boolean verifyPassword(String p, String h) { return p != null && h != null && passwordEncoder.matches(p, h); }

    public String encryptVault(String s) {
        if (s == null) return null;
        try {
            byte[] iv = new byte[IV_LENGTH_BYTE]; new SecureRandom().nextBytes(iv);
            Cipher c = Cipher.getInstance(ALGORITHM); c.init(Cipher.ENCRYPT_MODE, vaultKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(c.doFinal(s.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    public String decryptVault(String s) {
        if (s == null) return null;
        try {
            String[] p = s.split(":"); if (p.length != 2) return s;
            Cipher c = Cipher.getInstance(ALGORITHM); c.init(Cipher.DECRYPT_MODE, vaultKey, new GCMParameterSpec(TAG_LENGTH_BIT, Base64.getDecoder().decode(p[0])));
            return new String(c.doFinal(Base64.getDecoder().decode(p[1])), StandardCharsets.UTF_8);
        } catch (Exception e) { return null; }
    }

    @Transactional
    public Map<String, Object> establishSession(User u, String ip, String ua) {
        String rt = UUID.randomUUID().toString();
        UserSession s = new UserSession(); s.setUser(u); s.setRefreshTokenHash(hashPassword(rt)); s.setIpAddress(ip); s.setUserAgent(ua);
        s.setExpiry(LocalDateTime.now().plusDays(sessionExpiryDays)); userSessionRepository.save(s);
        return Map.of("accessToken", generateToken(u), "refreshToken", rt, "sessionId", s.getId().toString());
    }

    @Transactional
    public void revokeAllSessionsForUser(User u) {
        userSessionRepository.findAllByUserAndRevokedFalse(u).forEach(s -> { s.setRevoked(true); userSessionRepository.save(s); });
    }

    @Transactional
    public Map<String, Object> rotateSession(String rt, UUID sid, String ip, String ua) {
        UserSession old = userSessionRepository.findById(sid).orElse(null);
        if (old == null || old.isRevoked() || !verifyPassword(rt, old.getRefreshTokenHash())) {
            if (old != null) revokeAllSessionsForUser(old.getUser());
            throw new RuntimeException("Invalid Session");
        }
        old.setRevoked(true); userSessionRepository.save(old);
        String nextRt = UUID.randomUUID().toString();
        UserSession next = new UserSession(); next.setUser(old.getUser()); next.setRefreshTokenHash(hashPassword(nextRt));
        next.setParentTokenId(old.getId()); next.setIpAddress(ip); next.setUserAgent(ua);
        next.setExpiry(LocalDateTime.now().plusDays(sessionExpiryDays)); userSessionRepository.save(next);
        return Map.of("accessToken", generateToken(old.getUser()), "refreshToken", nextRt, "sessionId", next.getId().toString());
    }

    @Transactional
    public void recordFailedMfa(User u) {
        u.setFailedMfaAttempts(u.getFailedMfaAttempts() + 1);
        if (u.getFailedMfaAttempts() >= mfaMaxAttempts) {
            u.setStatus(User.AccountStatus.LOCKED); u.setLockedUntil(LocalDateTime.now().plusMinutes(mfaLockoutMins));
        }
        userRepository.save(u);
    }

    public boolean isStrongPassword(String p) {
        if (p == null || p.length() < minPasswordLength) return false;
        boolean u = false, l = false, d = false;
        for (char c : p.toCharArray()) { if (Character.isUpperCase(c)) u = true; else if (Character.isLowerCase(c)) l = true; else if (Character.isDigit(c)) d = true; }
        return u && l && d;
    }

    public String hashToken(String t) {
        try {
            var md = java.security.MessageDigest.getInstance("SHA-256");
            var h = md.digest(t.getBytes(StandardCharsets.UTF_8));
            var sb = new StringBuilder(); for (byte b : h) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    @Transactional
    public void triggerGlobalReset(String s) { if (lockdownSecretKey == null || !lockdownSecretKey.equals(s)) throw new RuntimeException("Invalid Secret"); }

    public String sanitize(String i) { return i == null ? null : HtmlUtils.htmlEscape(i.trim()); }

    public String sanitizeProfileImage(String i) {
        if (i == null || i.isBlank()) return defaultUserImage;
        if (i.startsWith("data:image/") && i.contains(";base64,") && i.matches("^data:image/[a-zA-Z]+;base64,[a-zA-Z0-9+/=]+$")) return i;
        if (i.startsWith("/images/") && !i.contains("..") && !i.contains("%")) return i;
        return defaultUserImage;
    }

    public boolean isSafeUrl(String u) { return resolveSafeUrl(u) != null; }

    public String resolveSafeUrl(String u) {
        if (u == null || u.isBlank()) return null;
        try {
            var url = new URL(u); var prot = url.getProtocol().toLowerCase(); if (!"http".equals(prot) && !"https".equals(prot)) return null;
            var host = url.getHost().toLowerCase(); var port = url.getPort() != -1 ? url.getPort() : url.getDefaultPort();
            if (allowedHosts != null && allowedHosts.stream().anyMatch(h -> h.equalsIgnoreCase(host)) && allowedPorts != null && allowedPorts.contains(port)) return new URL(prot, host, port, url.getFile()).toString();
            var addr = InetAddress.getByName(host);
            if (addr.isLoopbackAddress() || addr.isAnyLocalAddress() || addr.isLinkLocalAddress() || addr.isSiteLocalAddress() || "169.254.169.254".equals(addr.getHostAddress())) return null;
            return new URL(prot, addr.getHostAddress(), port, url.getFile()).toString();
        } catch (Exception e) { return null; }
    }

    public boolean isSafePath(String p, String b) {
        if (p == null || b == null || p.contains("\0")) return false;
        try {
            var base = Paths.get(b).toAbsolutePath().normalize(); var target = Paths.get(p).toAbsolutePath().normalize();
            if (java.nio.file.Files.exists(base)) base = base.toRealPath(); if (java.nio.file.Files.exists(target)) target = target.toRealPath();
            return target.startsWith(base);
        } catch (IOException e) { return false; }
    }

    public String processAndSaveImage(String data, String dir, String prefix) throws IOException {
        if (data == null || !data.contains(",")) throw new IOException("Invalid data");
        var bytes = Base64.getDecoder().decode(data.split(",")[1]);
        try (var bais = new ByteArrayInputStream(bytes)) {
            var img = ImageIO.read(bais); if (img == null) throw new IOException("Corrupted");
            var name = prefix + "_" + UUID.randomUUID().toString() + ".png"; var file = new File(dir, name);
            if (!isSafePath(file.getAbsolutePath(), new File(".").getAbsolutePath())) throw new IOException("Traversal");
            if (!ImageIO.write(img, "png", file)) throw new IOException("Failed write");
            return name;
        }
    }

    private final Map<String, List<Long>> hits = new ConcurrentHashMap<>();
    public boolean checkRateLimit(String ip, String act, int max, long win) {
        var key = ip + ":" + act; var now = System.currentTimeMillis();
        hits.putIfAbsent(key, Collections.synchronizedList(new LinkedList<>())); var ts = hits.get(key);
        synchronized (ts) { ts.removeIf(t -> now - t > win); if (ts.size() >= max) return false; ts.add(now); return true; }
    }

    @org.springframework.beans.factory.annotation.Value("${vulnprint.superadmin.email:superadmin@vulnprint.com}")
    private String superAdminEmail;
    public boolean isSuperAdmin(User u) { return u != null && superAdminEmail.equalsIgnoreCase(u.getEmail()); }
    public boolean hasPermission(User u, String k) {
        if (u == null || k == null) return false; if (isSuperAdmin(u)) return true;
        if (u.getRole() != null && u.getRole().getPermissions() != null && u.getRole().getPermissions().stream().anyMatch(p -> p.getName().equals(k))) return true;
        return u.getExtraPermissions() != null && u.getExtraPermissions().stream().anyMatch(p -> p.getName().equals(k));
    }

    private User getCurrentUser() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return (auth != null && auth.getPrincipal() instanceof User) ? (User) auth.getPrincipal() : null;
    }

    public boolean canViewProject(Long id) { User u = getCurrentUser(); return u != null && (hasPermission(u, VIEW_ALL_PROJECTS) || (hasPermission(u, VIEW_ASSIGNED_PROJECTS) && isAssignedToPentest(id))); }
    public boolean canEditProject(Long id) { User u = getCurrentUser(); return u != null && (hasPermission(u, EDIT_ALL_PROJECTS) || (hasPermission(u, EDIT_ASSIGNED_PROJECTS) && isAssignedToPentest(id))); }
    public boolean canDeleteProject(Long id) { User u = getCurrentUser(); return u != null && (hasPermission(u, DELETE_ALL_PROJECTS) || (hasPermission(u, DELETE_ASSIGNED_PROJECTS) && isAssignedToPentest(id))); }
    public boolean canViewVuln(Long id) { User u = getCurrentUser(); return u != null && (hasPermission(u, VIEW_ALL_VULNS) || (hasPermission(u, VIEW_ASSIGNED_VULNS) && isAssignedToVuln(id))); }
    public boolean canEditVuln(Long id) { User u = getCurrentUser(); return u != null && (hasPermission(u, EDIT_ALL_VULNS) || (hasPermission(u, EDIT_ASSIGNED_VULNS) && isAssignedToVuln(id))); }
    public boolean canDeleteVuln(Long id) { User u = getCurrentUser(); return u != null && (hasPermission(u, DELETE_ALL_VULNS) || (hasPermission(u, DELETE_ASSIGNED_VULNS) && isAssignedToVuln(id))); }
    public boolean canApproveVuln(Long id) { User u = getCurrentUser(); return u != null && (hasPermission(u, APPROVE_ALL_VULNS) || (hasPermission(u, APPROVE_ASSIGNED_VULNS) && isAssignedToVuln(id))); }
    public boolean isAssignedToPentest(Long id) { User u = getCurrentUser(); return u != null && id != null && pentestRepository.findById(id).map(p -> p.getAssignedPentesters().stream().anyMatch(at -> at.getId().equals(u.getId()))).orElse(false); }
    public boolean isAssignedToVuln(Long id) { User u = getCurrentUser(); return u != null && id != null && vulnerabilityRepository.findById(id).map(v -> v.getPentest() != null && v.getPentest().getAssignedPentesters().stream().anyMatch(at -> at.getId().equals(u.getId()))).orElse(false); }
    public boolean isSelf(Long id) { User u = getCurrentUser(); return u != null && u.getId().equals(id); }

    // Getters for Proxied Access
    public int getRatelimitAuthMax() { return ratelimitAuthMax; }
    public int getRatelimitAuthWindow() { return ratelimitAuthWindow; }
    public int getRatelimitViewsMax() { return ratelimitViewsMax; }
    public int getRatelimitViewsWindow() { return ratelimitViewsWindow; }

    @Component
    public static class JwtAuthenticationFilter extends OncePerRequestFilter {
        @Autowired private AppSecurityGuard guard;
        @Autowired private UserRepository userRepository;
        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
            var csrt = (org.springframework.security.web.csrf.CsrfToken) request.getAttribute(org.springframework.security.web.csrf.CsrfToken.class.getName());
            if (csrt != null) csrt.getToken();
            String token = null; var auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) token = auth.substring(7);
            else if (request.getCookies() != null) for (var c : request.getCookies()) if ("JWT".equals(c.getName())) { token = c.getValue(); break; }
            if (token != null && guard.validateToken(token)) {
                if (guard.isMfaOnlyToken(token)) { chain.doFilter(request, response); return; }
                var email = guard.getEmailFromToken(token);
                if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    final String ft = token;
                    userRepository.findActiveByEmail(email).ifPresent(u -> {
                        var iat = guard.getIssuedAtFromToken(ft);
                        boolean ok = true;
                        if (iat != null && u.getLastRoleChange() != null && iat.toInstant().isBefore(u.getLastRoleChange().atZone(java.time.ZoneId.systemDefault()).toInstant().minusMillis(500))) ok = false;
                        if (ok && u.isEnabled()) {
                            var autht = new UsernamePasswordAuthenticationToken(u, null, u.getAuthorities());
                            autht.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                            SecurityContextHolder.getContext().setAuthentication(autht);
                        }
                    });
                }
            }
            chain.doFilter(request, response);
        }
    }

    @Component
    public static class RateLimitingFilter extends OncePerRequestFilter {
        @Autowired private AppSecurityGuard guard;
        @Override
        protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
            var path = req.getRequestURI(); var ip = req.getRemoteAddr();
            if (path.startsWith("/api/auth/") || path.equals("/api/users/activate")) {
                if (!guard.checkRateLimit(ip, "AUTH", guard.getRatelimitAuthMax(), (long) guard.getRatelimitAuthWindow())) {
                    res.setStatus(429); res.setContentType("application/json"); res.getWriter().write("{\"message\": \"Rate limit exceeded.\"}"); return;
                }
            } else if (List.of("/", "/login", "/activate-account", "/error").contains(path)) {
                if (!guard.checkRateLimit(ip, "VIEWS", guard.getRatelimitViewsMax(), (long) guard.getRatelimitViewsWindow())) {
                    res.setStatus(429); res.setContentType("text/html"); res.getWriter().write("<h1>429 - Rate Limit Exceeded</h1>"); return;
                }
            }
            chain.doFilter(req, res);
        }
    }

    @Configuration @EnableWebSecurity @EnableMethodSecurity
    public static class SecurityConfig {
        @Autowired private JwtAuthenticationFilter jwtFilter;
        @Autowired private RateLimitingFilter rateFilter;
        @Bean public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }
        @Bean public org.springframework.web.cors.CorsConfigurationSource corsConfigurationSource() {
            var c = new org.springframework.web.cors.CorsConfiguration(); c.setAllowedOriginPatterns(List.of("*"));
            c.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
            c.setAllowedHeaders(List.of("Authorization", "Cache-Control", "Content-Type", "X-XSRF-TOKEN"));
            c.setExposedHeaders(List.of("X-XSRF-TOKEN")); c.setAllowCredentials(true);
            var s = new org.springframework.web.cors.UrlBasedCorsConfigurationSource(); s.registerCorsConfiguration("/**", c); return s;
        }
        @Bean public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            var rh = new org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler(); rh.setCsrfRequestAttributeName(null);
            http.cors(c -> c.configurationSource(corsConfigurationSource())).csrf(c -> c.csrfTokenRepository(org.springframework.security.web.csrf.CookieCsrfTokenRepository.withHttpOnlyFalse()).csrfTokenRequestHandler(rh).ignoringRequestMatchers(org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/auth/login"), org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/auth/apply"), org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/auth/verify-mfa"), org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/auth/refresh"), org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/users/activate")))
                .headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://unpkg.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: blob: https:; connect-src 'self' http://localhost:* http://127.0.0.1:* ws://localhost:* ws://127.0.0.1:*; frame-ancestors 'none'; form-action 'self';")).frameOptions(f -> f.deny()).xssProtection(x -> x.headerValue(org.springframework.security.web.header.writers.XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)).httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000)))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a.requestMatchers(org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/auth/**"), org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/users/activate"), org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/css/**"), org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/js/**"), org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/images/**"), org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/favicon.ico"), org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/"), org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/login"), org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/activate-account"), org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/reset-password"), org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/error")).permitAll()
                    .requestMatchers(org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher("/api/**")).authenticated()
                    .anyRequest().authenticated())
                .addFilterBefore(rateFilter, UsernamePasswordAuthenticationFilter.class).addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
            return http.build();
        }
    }
}
