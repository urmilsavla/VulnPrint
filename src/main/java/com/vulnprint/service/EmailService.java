package com.vulnprint.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender emailSender;

    public void sendInvitationEmail(String toEmail, String firstName, String activationLink) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("security@vulnprint.local");
        message.setTo(toEmail);
        message.setSubject("Action Required: VulnPrint Account Provisioned");
        message.setText("Hello " + firstName + ",\n\n" +
                "An administrator has provisioned a VulnPrint account for you.\n\n" +
                "Please click the link below to set your password and activate your account:\n" +
                activationLink + "\n\n" +
                "This link will expire in 24 hours.\n\n" +
                "Securely,\nThe VulnPrint Security Team");
        
        try {
            emailSender.send(message);
            System.out.println("[EMAIL SERVICE] Invitation email sent to " + toEmail);
        } catch (Exception e) {
            System.err.println("[EMAIL SERVICE] Failed to send invitation email to " + toEmail + ": " + e.getMessage());
        }
    }

    public void sendRejectionEmail(String toEmail, String firstName) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("security@vulnprint.local");
        message.setTo(toEmail);
        message.setSubject("Update: VulnPrint Access Request");
        message.setText("Hello " + firstName + ",\n\n" +
                "Your application for access to VulnPrint has been reviewed and declined at this time.\n\n" +
                "If you believe this is an error, please contact your security lead or system administrator.\n\n" +
                "Securely,\nThe VulnPrint Security Team");

        try {
            emailSender.send(message);
            System.out.println("[EMAIL SERVICE] Rejection email sent to " + toEmail);
        } catch (Exception e) {
            System.err.println("[EMAIL SERVICE] Failed to send rejection email to " + toEmail + ": " + e.getMessage());
        }
    }
}
