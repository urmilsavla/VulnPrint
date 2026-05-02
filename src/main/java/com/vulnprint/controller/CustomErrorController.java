package com.vulnprint.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class CustomErrorController implements ErrorController {

    @RequestMapping("/error")
    public String handleError(HttpServletRequest request, Model model) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        
        if (status != null) {
            int statusCode = Integer.parseInt(status.toString());
            model.addAttribute("code", statusCode);
            
            if (statusCode == HttpStatus.NOT_FOUND.value()) {
                model.addAttribute("message", "404 Not Found: The requested resource does not exist.");
            } else if (statusCode == HttpStatus.INTERNAL_SERVER_ERROR.value()) {
                model.addAttribute("message", "500 Internal Server Error: An unexpected condition was encountered.");
            } else if (statusCode == HttpStatus.FORBIDDEN.value()) {
                model.addAttribute("message", "403 Forbidden: You do not have permission to access this resource.");
            } else {
                model.addAttribute("message", "An unexpected error occurred.");
            }
        } else {
            model.addAttribute("code", "Error");
            model.addAttribute("message", "An unknown error occurred.");
        }
        
        return "error";
    }
}
