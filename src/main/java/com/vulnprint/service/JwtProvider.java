package com.vulnprint.service;

import com.vulnprint.model.Permission;
import com.vulnprint.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class JwtProvider {

    // In a production app, this should be loaded from a secure configuration
    private final SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private final long expirationMs = 86400000; // 24 hours

    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getRole() != null ? user.getRole().getName() : "None");
        
        // Consolidate all permissions into a flat list for the JWT
        Set<String> permissions = user.getRole() != null ? 
            user.getRole().getPermissions().stream().map(Permission::getName).collect(Collectors.toSet()) : 
            new java.util.HashSet<>();
        
        if (user.getExtraPermissions() != null) {
            permissions.addAll(user.getExtraPermissions().stream().map(Permission::getName).collect(Collectors.toSet()));
        }
        
        claims.put("perms", permissions);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(key)
                .compact();
    }

    public String getUsernameFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
