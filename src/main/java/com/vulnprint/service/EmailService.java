package com.vulnprint.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender emailSender;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.email.from-address:security@vulnprint.local}")
    private String fromAddress;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.email.subject.invitation:Action Required: VulnPrint Account Provisioned}")
    private String subjectInvitation;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.email.subject.rejection:Update: VulnPrint Access Request}")
    private String subjectRejection;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.email.subject.mfa-otp:VulnPrint Security: Your MFA Verification Code}")
    private String subjectMfa;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.email.subject.password-reset:Security Notification: Password Reset Requested}")
    private String subjectReset;

    @org.springframework.beans.factory.annotation.Value("${vulnprint.email.signature:The VulnPrint Security Team}")
    private String emailSignature;

    public void sendInvitationEmail(String toEmail, String firstName, String activationLink) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(toEmail);
        message.setSubject(subjectInvitation);
        message.setText("Hello " + firstName + ",\n\n" +
                "An administrator has provisioned a VulnPrint account for you.\n\n" +
                "Please click the link below to set your password and activate your account:\n" +
                activationLink + "\n\n" +
                "This link will expire in 24 hours.\n\n" +
                "Securely,\n" + emailSignature);
        
        try {
            emailSender.send(message);
            System.out.println("[EMAIL SERVICE] Invitation email sent to " + toEmail);
        } catch (Exception e) {
            System.err.println("[EMAIL SERVICE] Failed to send invitation email to " + toEmail + ": " + e.getMessage());
        }
    }

    public void sendRejectionEmail(String toEmail, String firstName) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(toEmail);
        message.setSubject(subjectRejection);
        message.setText("Hello " + firstName + ",\n\n" +
                "Your application for access to VulnPrint has been reviewed and declined at this time.\n\n" +
                "If you believe this is an error, please contact your security lead or system administrator.\n\n" +
                "Securely,\n" + emailSignature);

        try {
            emailSender.send(message);
            logger.info("[EMAIL SERVICE] Rejection email sent to " + toEmail);
        } catch (Exception e) {
            System.err.println("[EMAIL SERVICE] Failed to send rejection email to " + toEmail + ": " + e.getMessage());
        }
    }

    public void sendMfaOtp(String to, String otp) throws Exception {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(to);
        message.setSubject(subjectMfa);
        message.setText("Your verification code is: " + otp + "\n\nThis code will expire in 5 minutes.\nIf you did not request this code, please secure your account immediately.\n\nSecurely,\n" + emailSignature);
        
        try {
            emailSender.send(message);
            logger.info("[EMAIL SERVICE] MFA OTP sent to " + to);
        } catch (Exception e) {
            System.err.println("[EMAIL SERVICE] Failed to send MFA OTP to " + to + ": " + e.getMessage());
            throw e; // Rethrow to allow controller to handle failure
        }
    }

    public void sendPasswordResetEmail(String toEmail, String firstName, String resetLink) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(toEmail);
        message.setSubject(subjectReset);
        message.setText("Hello " + firstName + ",\n\n" +
                "An administrator has initiated a password reset for your VulnPrint account.\n\n" +
                "Please click the link below to set your new password:\n" +
                resetLink + "\n\n" +
                "This link will expire in 15 minutes.\n\n" +
                "If you did not request this, please notify your administrator immediately.\n\n" +
                "Securely,\n" + emailSignature);
        
        try {
            emailSender.send(message);
            System.out.println("[EMAIL SERVICE] Password reset email sent to " + toEmail);
        } catch (Exception e) {
            logger.error("[EMAIL SERVICE] Failed to send password reset email to " + toEmail + ": " + e.getMessage(), e);
        }
    }
}

n e) {
            logger.error("[EMAIL SERVICE] Failed to send password reset email to " + toEmail + ": " + e.getMessage(), e);
        }
    }
}



