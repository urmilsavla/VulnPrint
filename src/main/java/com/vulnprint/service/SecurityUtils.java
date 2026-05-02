package com.vulnprint.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.util.HtmlUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class SecurityUtils {

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

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
