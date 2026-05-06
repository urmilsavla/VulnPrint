package com.vulnprint.security;

import com.vulnprint.model.Permission;
import com.vulnprint.model.User;
import com.vulnprint.repository.UserRepository;
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
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
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

import javax.crypto.SecretKey;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * AppSecurityGuard: The Monolithic Security Core of VulnPrint.
 * Consolidates Authentication, Sanitization, SSRF Shielding, Rate Limiting, and File Integrity.
 */
@Component
public class AppSecurityGuard {

    @Autowired
    @Lazy
    private PasswordEncoder passwordEncoder;

    // --- 1. JWT & CRYPTO PILLAR ---
    private final SecretKey jwtKey;
    private final long expirationMs = 900000; // 15 minutes for enhanced security
    private final Set<String> tokenBlocklist = ConcurrentHashMap.newKeySet();

    public AppSecurityGuard() {
        String envKey = System.getenv("VULNPRINT_JWT_SECRET");
        if (envKey != null && envKey.length() >= 32) {
            this.jwtKey = Keys.hmacShaKeyFor(envKey.getBytes(StandardCharsets.UTF_8));
        } else {
            this.jwtKey = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS256);
        }
    }

    public void blockToken(String token) {
        if (token != null) {
            tokenBlocklist.add(token);
        }
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

    public String getUsernameFromToken(String token) {
        try {
            return Jwts.parserBuilder().setSigningKey(jwtKey).build().parseClaimsJws(token).getBody().getSubject();
        } catch (Exception e) { return null; }
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

    // --- 2. XSS & SANITIZATION PILLAR ---
    public String sanitize(String input) {
        if (input == null) return null;
        return HtmlUtils.htmlEscape(input.trim());
    }

    public String sanitizeProfileImage(String input) {
        if (input == null || input.isBlank()) return "/images/user.png";
        // Allow safe base64 images
        if (input.startsWith("data:image/") && input.contains(";base64,")) {
            // Further validate that it's just base64 data
            if (input.matches("^data:image/[a-zA-Z]+;base64,[a-zA-Z0-9+/=]+$")) return input;
        }
        // Allow local image paths
        if (input.startsWith("/images/") && !input.contains("..") && !input.contains("%")) {
            return input;
        }
        return "/images/user.png";
    }

    // --- 3. SSRF SHIELD PILLAR ---
    public boolean isSafeUrl(String urlString) {
        if (urlString == null || urlString.isBlank()) return false;
        try {
            URL url = new URL(urlString);
            String protocol = url.getProtocol().toLowerCase();
            if (!"http".equals(protocol) && !"https".equals(protocol)) return false;

            InetAddress address = InetAddress.getByName(url.getHost());
            if (address.isLoopbackAddress() || address.isAnyLocalAddress() || 
                address.isLinkLocalAddress() || address.isSiteLocalAddress()) return false;
            if ("169.254.169.254".equals(address.getHostAddress())) return false;
            return true;
        } catch (Exception e) { return false; }
    }

    // --- 4. FILE & RCE SHIELD PILLAR ---
    public boolean isSafePath(String requestedPath, String baseDir) {
        if (requestedPath == null || baseDir == null || requestedPath.contains("\0")) return false;
        try {
            Path base = Paths.get(baseDir).toRealPath();
            Path target = Paths.get(requestedPath).toRealPath();
            return target.startsWith(base);
        } catch (IOException e) { return false; }
    }

    public String processAndSaveImage(String base64Data, String uploadDir, String fileNamePrefix) throws IOException {
        if (base64Data == null || !base64Data.contains(",")) throw new IOException("Invalid image data");
        String[] parts = base64Data.split(",");
        byte[] imageBytes = Base64.getDecoder().decode(parts[1]);

        try (ByteArrayInputStream bais = new ByteArrayInputStream(imageBytes)) {
            BufferedImage image = ImageIO.read(bais);
            if (image == null) throw new IOException("Not a valid image or corrupted format");
            String fileName = fileNamePrefix + "_" + UUID.randomUUID().toString() + ".png";
            File outputFile = new File(uploadDir, fileName);
            if (!isSafePath(outputFile.getAbsolutePath(), uploadDir)) throw new IOException("Path traversal blocked");
            if (!ImageIO.write(image, "png", outputFile)) throw new IOException("Critical failure writing safe image to disk");
            return fileName;
        }
    }

    // --- 5. RATE LIMITING PILLAR ---
    private final Map<String, List<Long>> hits = new ConcurrentHashMap<>();

    public boolean checkRateLimit(String ip, String action, int maxRequests, long windowMs) {
        String key = ip + ":" + action;
        long now = System.currentTimeMillis();
        hits.putIfAbsent(key, Collections.synchronizedList(new ArrayList<>()));
        List<Long> timestamps = hits.get(key);

        synchronized (timestamps) {
            timestamps.removeIf(t -> now - t > windowMs);
            if (timestamps.size() >= maxRequests) return false;
            timestamps.add(now);
            return true;
        }
    }

    public boolean hasPermission(User user, String key) {
        if (user == null || key == null) return false;
        if (user.getRole() != null && user.getRole().getPermissions() != null) {
            if (user.getRole().getPermissions().stream().anyMatch(p -> p.getName().equals(key))) return true;
        }
        if (user.getExtraPermissions() != null) {
            return user.getExtraPermissions().stream().anyMatch(p -> p.getName().equals(key));
        }
        return false;
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
                String username = guard.getUsernameFromToken(token);
                final String finalToken = token;
                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    userRepository.findByUsername(username).ifPresent(user -> {
                        Date issuedAt = guard.getIssuedAtFromToken(finalToken);
                        if (issuedAt != null && user.getLastRoleChange() != null) {
                            java.time.Instant lastChangeInstant = user.getLastRoleChange().atZone(java.time.ZoneId.systemDefault()).toInstant();
                            if (issuedAt.toInstant().isBefore(lastChangeInstant)) return;
                        }
                        if (user.isEnabled()) {
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

    @Configuration
    @EnableWebSecurity
    @EnableMethodSecurity
    public static class SecurityConfig {
        @Autowired
        private JwtAuthenticationFilter jwtAuthenticationFilter;

        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http
                .csrf(csrf -> csrf
                    .csrfTokenRepository(org.springframework.security.web.csrf.CookieCsrfTokenRepository.withHttpOnlyFalse())
                    .ignoringRequestMatchers("/api/auth/login")
                )
                .headers(headers -> headers
                    .contentSecurityPolicy(csp -> csp
                        .policyDirectives("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://unpkg.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';")
                    )
                    .frameOptions(frame -> frame.deny())
                    .xssProtection(xss -> xss.headerValue(org.springframework.security.web.header.writers.XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                    .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/api/auth/login").permitAll()
                    .requestMatchers("/css/**", "/js/**", "/images/**", "/favicon.ico").permitAll()
                    .requestMatchers("/", "/login", "/error").permitAll()
                    .requestMatchers("/dashboard", "/web-pentest", "/mobile-pentest", "/api-pentest", "/network-pentest", "/source-code-pentest", "/template-guide", "/vulnerability-approver", "/user-management", "/organization-settings", "/microservice-management", "/manage-access", "/generate-report", "/reset-password", "/profile", "/pentest/**").authenticated()
                    .requestMatchers("/api/**").authenticated()
                    .anyRequest().denyAll()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

            return http.build();
        }
    }
}
