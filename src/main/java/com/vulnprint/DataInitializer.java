package com.vulnprint;

import com.vulnprint.model.Pentest;
import com.vulnprint.model.Vulnerability;
import com.vulnprint.model.VulnerabilityStep;
import com.vulnprint.model.Alert;
import com.vulnprint.model.User;
import com.vulnprint.repository.PentestRepository;
import com.vulnprint.repository.VulnerabilityRepository;
import com.vulnprint.repository.AlertRepository;
import com.vulnprint.repository.UserRepository;
import com.vulnprint.service.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import org.springframework.jdbc.core.JdbcTemplate;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private PentestRepository pentestRepository;
    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;
    @Autowired
    private AlertRepository alertRepository;
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private SecurityUtils securityUtils;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public void run(String... args) throws Exception {
        // Data now persists across restarts. 
        // We only initialize mandatory users if the database is empty.
        initializeUsers();
    }

    @Transactional
    public void initializeUsers() {
        if (userRepository.findAll().isEmpty()) {
            User admin = createUser("admin", "admin123", "admin@vulnprint.com", "Administrator", "User", "Administrator", "Global HQ", "CISSP, CISM, OSCP, Lead Security Manager");
            User urmil = createUser("urmil", "urmil123", "urmil@vulnprint.com", "Urmil", "Savla", "Lead Pentester", "Mumbai Office", "OSCP, CRT, CEH");
            User jinesh = createUser("jinesh", "jinesh123", "jinesh@vulnprint.com", "Jinesh", "Savla", "Lead Pentester", "Dubai Office", "OSWE, GXPN, CISSP");
        }
    }

    private User createUser(String user, String pass, String email, String first, String last, String role, String address, String qualification) {
        User u = new User();
        u.setUsername(user); 
        u.setPassword(securityUtils.hashPassword(pass)); 
        u.setEmail(email); u.setFirstName(first); u.setLastName(last); u.setRole(role); u.setAddress(address); u.setQualification(qualification);
        return userRepository.save(u);
    }
}
