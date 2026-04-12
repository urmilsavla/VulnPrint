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
    private JdbcTemplate jdbcTemplate;

    @Override
    public void run(String... args) throws Exception {
        // Data now persists across restarts. 
        // We only initialize mandatory users if the registry is empty.
        initializeUsers();
    }

    @Transactional
    public void initializeUsers() {
        if (userRepository.findAll().isEmpty()) {
            createUser("admin", "admin123", "admin@vulnprint.com", "Administrator", "User", "Administrator", "Global HQ");
            createUser("urmil", "urmil123", "urmil@vulnprint.com", "Urmil", "Savla", "Lead Pentester", "Mumbai Node");
            createUser("jinesh", "jinesh123", "jinesh@vulnprint.com", "Jinesh", "Savla", "Lead Pentester", "Dubai Node");

            // Seed some initial system alerts for the dashboard feed
            createAlert("System", "DATABASE_ONLINE", "Secure project registry is now operational.");
            createAlert("System", "NODE_SYNC_COMPLETE", "All intelligence nodes are synchronized.");
            createAlert("System", "ENCRYPTION_ACTIVE", "AES-256 field level encryption is active.");
        }
    }

    private void createAlert(String level, String title, String details) {
        Alert a = new Alert();
        a.setLevel(level);
        a.setTitle(title);
        a.setDetails(details);
        a.setTimeAgo("Just now");
        alertRepository.save(a);
    }

    private User createUser(String user, String pass, String email, String first, String last, String role, String address) {
        User u = new User();
        u.setUsername(user); u.setPassword(pass); u.setEmail(email); u.setFirstName(first); u.setLastName(last); u.setRole(role); u.setAddress(address);
        return userRepository.save(u);
    }

    private Pentest createPentest(String appName, String clientName, String type, String leadUsername, List<User> pentesters) {
        Pentest p = new Pentest();
        p.setApplicationName(appName); p.setClientName(clientName); p.setTarget(appName + " Scope");
        p.setPentestType(type); p.setStatus("Active");
        p.setCreatedDate(LocalDateTime.now());
        p.setAssignedPentesters(new ArrayList<>(pentesters));
        return p;
    }

    private void addVuln(Pentest p, String title, String sev, Double cvss, String owasp, String cwe) {
        Vulnerability v = new Vulnerability();
        v.setTitle(title); v.setSeverity(sev); v.setCvssScore(cvss); v.setOwasp(owasp); v.setCweReference(cwe);
        v.setStatus("Submitted"); v.setPentest(p);
        v.setDescription("Technical breakdown for " + title);
        v.setImpact("Business impact analysis for " + title);
        v.setMitigation("Standard mitigation procedure for " + title);
        
        VulnerabilityStep s1 = new VulnerabilityStep();
        s1.setStepNumber(1); s1.setDescription("Identify the vulnerable component."); s1.setVulnerability(v);
        v.setSteps(Arrays.asList(s1));
        
        vulnerabilityRepository.save(v);
    }
}
