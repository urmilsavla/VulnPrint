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
        initializeConfigs();
    }

    @Transactional
    public void initializeConfigs() {
        jdbcTemplate.execute("INSERT INTO system_configs (config_key, config_value) VALUES ('vulndb_enabled', 'true') ON CONFLICT (config_key) DO NOTHING");
        jdbcTemplate.execute("INSERT INTO system_configs (config_key, config_value) VALUES ('repgen_enabled', 'true') ON CONFLICT (config_key) DO NOTHING");
    }

    @Transactional
    public void initializeUsers() {
        List<User> users = userRepository.findAll();
        System.out.println("Total users found in DB: " + users.size());
        if (users.isEmpty()) {
            System.out.println("No users found. Creating default users...");
            createUser("admin", "admin123", "admin@vulnprint.com", "Administrator", "User", "Administrator", "Global HQ", "CISSP, CISM, OSCP, Lead Security Manager");
            createUser("urmil", "urmil123", "urmil@vulnprint.com", "Urmil", "Savla", "Lead Pentester", "Mumbai Office", "OSCP, CRT, CEH");
            createUser("jinesh", "jinesh123", "jinesh@vulnprint.com", "Jinesh", "Savla", "Lead Pentester", "Dubai Office", "OSWE, GXPN, CISSP");
            System.out.println("Default users created.");
        } else {
            // Fix for existing users with plaintext passwords from older versions
            for (User u : users) {
                if (u.getPassword() != null && !u.getPassword().startsWith("$2a$") && !u.getPassword().startsWith("$2b$") && !u.getPassword().startsWith("$2y$")) {
                    System.out.println("Hashing plaintext password for user: " + u.getUsername());
                    u.setPassword(securityUtils.hashPassword(u.getPassword()));
                    userRepository.save(u);
                }
            }
        }
    }

    private User createUser(String user, String pass, String email, String first, String last, String role, String address, String qualification) {
        User u = new User();
        u.setUsername(user); 
        u.setPassword(securityUtils.hashPassword(pass)); 
        u.setEmail(email); u.setFirstName(first); u.setLastName(last); u.setRole(role); u.setAddress(address); u.setQualification(qualification);
        System.out.println("Saving user: " + user);
        return userRepository.save(u);
    }
}
