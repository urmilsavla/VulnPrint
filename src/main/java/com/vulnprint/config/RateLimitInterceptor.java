package com.vulnprint.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    private final Map<String, RequestCounter> requestCounts = new ConcurrentHashMap<>();
    private static final int MAX_REQUESTS = 10;
    private static final long TIME_WINDOW = TimeUnit.MINUTES.toMillis(1);

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String ip = request.getRemoteAddr();
        long currentTime = System.currentTimeMillis();

        requestCounts.compute(ip, (key, counter) -> {
            if (counter == null || (currentTime - counter.startTime) > TIME_WINDOW) {
                return new RequestCounter(currentTime, new AtomicInteger(1));
            }
            counter.count.incrementAndGet();
            return counter;
        });

        if (requestCounts.get(ip).count.get() > MAX_REQUESTS) {
            response.setStatus(429); // Too Many Requests
            response.getWriter().write("{\"error\": \"Rate limit exceeded. Please try again later.\"}");
            response.setContentType("application/json");
            return false;
        }

        return true;
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
