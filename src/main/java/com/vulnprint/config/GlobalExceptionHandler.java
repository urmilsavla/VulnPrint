package com.vulnprint.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.ModelAndView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AccessDeniedException.class)
    public Object handleAccessDenied(AccessDeniedException ex, HttpServletRequest request) {
        String correlationId = UUID.randomUUID().toString();
        logger.warn("Access Denied [ID: {}]: {}", correlationId, ex.getMessage());
        
        // The frontend interceptor in header.html will provide specific action names.
        // This backend message serves as a professional fallback.
        String message = "You do not have permission to perform this action.";

        if (request.getRequestURI().startsWith("/api/")) {
            Map<String, Object> body = new HashMap<>();
            body.put("message", message);
            body.put("correlationId", correlationId);
            body.put("status", HttpStatus.FORBIDDEN.value());
            
            return new ResponseEntity<>(body, HttpStatus.FORBIDDEN);
        } else {
            ModelAndView mav = new ModelAndView("error");
            mav.addObject("code", 403);
            mav.addObject("message", message);
            return mav;
        }
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("status", HttpStatus.BAD_REQUEST.value());
        
        body.put("message", "Please fill in all required fields marked with an asterisk (*).");
        return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public Object handleAllExceptions(Exception ex, HttpServletRequest request) {
        if (ex.getClass().getName().contains("AuthenticationException") || ex.getClass().getName().contains("AuthenticationCredentialsNotFoundException")) {
            return handleAccessDenied(new AccessDeniedException("Not Authenticated"), request);
        }

        String correlationId = UUID.randomUUID().toString();
        logger.error("Internal Server Error [ID: {}]", correlationId, ex);
        
        if (request.getRequestURI().startsWith("/api/")) {
            Map<String, Object> body = new HashMap<>();
            body.put("message", "An unexpected error occurred. Please contact support and provide the Correlation ID.");
            body.put("correlationId", correlationId);
            body.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
            
            return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
        } else {
            ModelAndView mav = new ModelAndView("error");
            mav.addObject("code", 500);
            mav.addObject("message", "Internal Server Error. Correlation ID: " + correlationId);
            return mav;
        }
    }
}
