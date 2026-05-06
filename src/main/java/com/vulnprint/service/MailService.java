package com.vulnprint.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailService {

    @Autowired
    private JavaMailSender mailSender;

    public void sendMfaOtp(String to, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("security@vulnprint.local");
        message.setTo(to);
        message.setSubject("VulnPrint Security: Your MFA Verification Code");
        message.setText("Your verification code is: " + otp + "\n\nThis code will expire in 5 minutes.\nIf you did not request this code, please secure your account immediately.");
        
        mailSender.send(message);
    }
}
