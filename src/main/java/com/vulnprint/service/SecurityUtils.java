package com.vulnprint.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.util.HtmlUtils;

import java.io.File;
import java.io.IOException;

import com.vulnprint.model.User;

@Service
public class SecurityUtils {

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Checks if the user has a specific permission key.
     */
    public boolean hasPermission(User user, String key) {
        if (user == null || key == null) return false;
        
        // Check role permissions
        if (user.getRole() != null && user.getRole().getPermissions() != null) {
            if (user.getRole().getPermissions().stream().anyMatch(p -> p.getName().equals(key))) {
                return true;
            }
        }
        
        // Check extra permissions
        if (user.getExtraPermissions() != null) {
            return user.getExtraPermissions().stream().anyMatch(p -> p.getName().equals(key));
        }
        
        return false;
    }

    /**
     * Prevents Path Traversal by validating that a file path is within the base directory.
     */
    public boolean validateFilePath(String requestedPath, String baseDir) {
        if (requestedPath == null || baseDir == null) return false;
        try {
            File base = new File(baseDir).getCanonicalFile();
            File file = new File(requestedPath).getCanonicalFile();
            
            // Check if the file's canonical path starts with the base directory's canonical path
            return file.getPath().startsWith(base.getPath());
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Encodes a string for safe output in HTML to prevent XSS.
     */
    public String encodeForHTML(String input) {
        if (input == null) return null;
        return HtmlUtils.htmlEscape(input);
    }

    /**
     * Hashes a plaintext password using BCrypt.
     */
    public String hashPassword(String plaintext) {
        if (plaintext == null) return null;
        return passwordEncoder.encode(plaintext);
    }

    /**
     * Verifies a plaintext password against a BCrypt hash.
     */
    public boolean verifyPassword(String plaintext, String hash) {
        if (plaintext == null || hash == null) return false;
        return passwordEncoder.matches(plaintext, hash);
    }
}
