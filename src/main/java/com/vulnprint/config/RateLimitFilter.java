package com.vulnprint.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class RateLimitFilter implements Filter {

    private final Map<String, RequestCounter> requestCounts = new ConcurrentHashMap<>();
    
    // Global limits
    private static final int MAX_REQUESTS_GLOBAL = 300;
    private static final long TIME_WINDOW_GLOBAL = TimeUnit.MINUTES.toMillis(1);

    // Strict limits for sensitive operations (Login, Create, Update, Delete)
    private static final int MAX_REQUESTS_STRICT = 50;
    private static final long TIME_WINDOW_STRICT = TimeUnit.MINUTES.toMillis(1);
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        String ip = httpRequest.getRemoteAddr();
        String method = httpRequest.getMethod();
        String path = httpRequest.getRequestURI();
        long currentTime = System.currentTimeMillis();

        boolean isStrict = method.equals("POST") || method.equals("PUT") || method.equals("PATCH") || method.equals("DELETE") || path.contains("/api/auth/login");
        
        String key = ip + (isStrict ? ":STRICT" : ":GLOBAL");
        int maxRequests = isStrict ? MAX_REQUESTS_STRICT : MAX_REQUESTS_GLOBAL;
        long timeWindow = isStrict ? TIME_WINDOW_STRICT : TIME_WINDOW_GLOBAL;

        RequestCounter counter = requestCounts.compute(key, (k, v) -> {
            if (v == null || (currentTime - v.startTime) > timeWindow) {
                return new RequestCounter(currentTime, new AtomicInteger(1));
            }
            v.count.incrementAndGet();
            return v;
        });

        if (counter.count.get() > maxRequests) {
            httpResponse.setStatus(429);
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write("{\"error\": \"Rate limit exceeded. Too many " + (isStrict ? "sensitive " : "") + "requests from your IP.\"}");
            return;
        }

        chain.doFilter(request, response);
    }

    private static class RequestCounter {
        long startTime;
        AtomicInteger count;

        RequestCounter(long startTime, AtomicInteger count) {
            this.startTime = startTime;
            this.count = count;
        }
    }
}
