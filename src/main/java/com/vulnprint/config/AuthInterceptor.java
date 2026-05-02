package com.vulnprint.config;

import com.vulnprint.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class AuthInterceptor implements HandlerInterceptor {

    @Autowired
    private UserRepository userRepository;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // Skip pre-flight requests
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }

        String token = request.getHeader("X-Auth-Token");

        if (token != null && !token.isEmpty()) {
            var userOpt = userRepository.findByUsername(token);
            if (userOpt.isPresent()) {
                // Store the authenticated user in the request for IDOR checks in controllers
                request.setAttribute("authenticatedUser", userOpt.get());
                return true;
            }
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("{\"error\": \"Unauthorized: Please log in to access this resource\"}");
        response.setContentType("application/json");
        return false;
    }
}
