package com.vulnprint.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class SecurityHeadersFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        // Prevent Clickjacking
        httpResponse.setHeader("X-Frame-Options", "DENY");
        
        // Prevent MIME-sniffing
        httpResponse.setHeader("X-Content-Type-Options", "nosniff");
        
        // Basic Content Security Policy (allows inline scripts/styles for this specific project UI)
        httpResponse.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://unpkg.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' *;");
        
        // Enable HSTS (1 year)
        httpResponse.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        
        // Referrer Policy
        httpResponse.setHeader("Referrer-Policy", "no-referrer-when-downgrade");

        chain.doFilter(request, response);
    }
}
