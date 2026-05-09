package com.vulnprint;

import com.vulnprint.model.*;
import com.vulnprint.repository.*;
import com.vulnprint.security.AppSecurityGuard;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@Component
@Order(2)
public class DataInitializerPartTwo implements CommandLineRunner {

    @Autowired
    private PentestRepository pentestRepository;
    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private OrganizationRepository organizationRepository;
    @Autowired
    private AppSecurityGuard guard;

    @Override
    @Transactional
    public void run(String... args) throws Exception {
        initializeOrganization();

        if (pentestRepository.count() > 0) {
            // Already initialized some data, but let's add our "historical" data if it's not there
            if (pentestRepository.count() > 5) return; 
        }

        System.out.println("[SYSTEM] Initializing DataInitializer Part Two: Historical Records...");

        // 1. Initialize Roles and Additional Pentesters
        Role pentesterRole = initializePentesterRole();
        Role auditorRole = initializeAuditorRole();
        
        User aarav = createTester("aarav.sharma@vulnprint.com", "Aarav", "Sharma", pentesterRole, 
                "B.Tech Computer Science, CISSP, CEH", "142 Innovation Park, South Cyber City");
        User zoe = createTester("zoe.chen@vulnprint.com", "Zoe", "Chen", auditorRole, 
                "M.Sc. Information Security, GWAPT, GMOB", "88 Silicon Valley Ave, Tech Hub");
        User urmil = userRepository.findByEmail("urmilsavla108@gmail.com").orElse(null);

        // Ensure aarav and zoe have the correct roles if they already existed as Admins
        aarav.setRole(pentesterRole);
        zoe.setRole(auditorRole);
        userRepository.save(aarav);
        userRepository.save(zoe);

        // 2. Project 1: Web Application (Global Fintech Portal)
        Pentest fintech = createProject("Fintech Core Banking Portal", "Global Fintech Group", "Web", 
                "https://banking.globalfintech.com", "Spring Boot 3.1, React 18, PostgreSQL 15", 
                safeList(urmil, aarav), "Active", "Marcus Vane", "mvane@globalfintech.com", "v1.4.2-stable");
        populateFintechVulns(fintech);

        // 3. Project 2: Mobile Application (HealthTrack Pro)
        Pentest health = createProject("HealthTrack Pro Mobile", "BioHealth Solutions", "Mobile", 
                "Android & iOS App", "Flutter 3.10, Firebase, Node.js 18", 
                safeList(zoe), "Active", "Dr. Sarah Jenkins", "s.jenkins@biohealth.io", "v2.0.1-build88");
        health.setPackageName("com.biohealth.trackpro");
        health.setOsType("Android 13 / iOS 16");
        pentestRepository.save(health);
        populateHealthVulns(health);

        // 4. Project 3: API Service (Logistics Connect API)
        Pentest logistics = createProject("Logistics Connect REST API", "SwiftLogistics Inc", "API", 
                "https://api.swiftlogistics.io/v1", "Node.js 20, Express 4.18, MongoDB 6.0", 
                safeList(urmil, zoe), "Active", "Kevin Wright", "k.wright@swiftlogistics.io", "v3.0.0-rc1");
        logistics.setApiDomain("api.swiftlogistics.io");
        logistics.setApiType("REST/JSON with OAuth2");
        pentestRepository.save(logistics);
        populateLogisticsVulns(logistics);

        // 5. Project 4: Infrastructure Audit (Corporate DMZ Environment)
        Pentest infra = createProject("Corporate DMZ Infrastructure", "Apex Corp", "Network", 
                "10.50.0.0/24, 172.16.10.0/24", "Cisco Catalyst, Fortinet FG-100F, Windows Server 2022", 
                safeList(aarav), "Active", "Elena Rodriguez", "e.rodriguez@apex-corp.com", "Infrastructure Audit Q2 2026");
        infra.setIpRanges("10.50.0.0/24, 172.16.10.0/24, 45.76.12.11, 45.76.12.12");
        infra.setTargetType("External & Internal Segments");
        pentestRepository.save(infra);
        populateInfraVulns(infra);

        // 6. Project 5: Source Code Review (Legacy Authentication Module)
        Pentest source = createProject("AuthEngine Legacy Review", "SecureAuth Ltd", "Source Code", 
                "https://github.com/secureauth/authengine-legacy", "Java 17, Maven 3.9, Spring Security 6", 
                safeList(urmil), "Active", "James O'Brian", "jobrian@secureauth.com", "Commit: 7a8b9c0d");
        source.setLanguage("Java / Spring");
        source.setRepoUrl("https://github.com/secureauth/authengine-legacy");
        source.setBranchName("main-production");
        pentestRepository.save(source);
        populateSourceVulns(source);

        // 7. Project 6: Web Application (Internal SaaS HR Dashboard)
        Pentest hr = createProject("Internal Employee Portal", "CloudStaffing SaaS", "Web", 
                "https://hr.internal.cloudstaffing.net", "PHP 8.2, Laravel 10, MySQL 8", 
                safeList(zoe, urmil), "Completed", "Linda Chen", "l.chen@cloudstaffing.net", "v5.5.0");
        pentestRepository.save(hr);
        populateHRVulns(hr);

        System.out.println("[SYSTEM] Historical Records successfully populated.");
    }

    private List<User> safeList(User... users) {
        List<User> list = new ArrayList<>();
        if (users != null) {
            for (User u : users) {
                if (u != null) list.add(u);
            }
        }
        return list;
    }

    private User createTester(String email, String first, String last, Role role, String qualification, String address) {
        return userRepository.findByEmail(email).orElseGet(() -> {
            User u = new User();
            u.setEmail(email);
            u.setFirstName(first);
            u.setLastName(last);
            u.setPassword(guard.hashPassword("VulnPrintTester123!"));
            u.setRole(role);
            u.setEnabled(true);
            u.setStatus(User.AccountStatus.ACTIVE);
            u.setQualification(guard.sanitize(qualification));
            u.setAddress(guard.encryptVault(guard.sanitize(address)));
            return userRepository.save(u);
        });
    }

    private Pentest createProject(String name, String client, String type, String target, String tech, List<User> testers, String status, String spocName, String spocContact, String version) {
        Pentest p = new Pentest();
        p.setPentestName(name);
        p.setApplicationName(name);
        p.setClientName(client);
        p.setPentestType(type);
        p.setTarget(target);
        p.setTechStack(tech);
        p.setAssignedPentesters(new ArrayList<>(testers));
        p.setStatus(status);
        p.setClientSpocName(spocName);
        p.setClientSpocContact(spocContact);
        p.setVersion(version);
        p.setCreatedDate(LocalDateTime.now().minusMonths(3));
        p.setLastModifiedDate(LocalDateTime.now().minusDays(2));
        
        // Report settings
        p.setOrganizationName("VulnPrint Security");
        p.setDisclaimer("This report contains sensitive information. Unauthorized distribution is prohibited.");
        p.setExecutiveSummary("This assessment evaluated the security posture of " + name + ".");
        
        return pentestRepository.save(p);
    }

    private void addVuln(Pentest p, String title, String severity, Double score, String status, String reportingStatus, String vulnStatus, String desc, String impact, String mitigation, String cwe, String owasp, String evidenceMode, List<VulnerabilityStep> steps) {
        Vulnerability v = new Vulnerability();
        v.setPentest(p);
        v.setTitle(title);
        v.setSeverity(severity);
        v.setCvssScore(score);
        v.setStatus(status);
        v.setReportingStatus(reportingStatus);
        v.setVulnerabilityStatus(vulnStatus);
        v.setDescription(desc);
        v.setImpact(impact);
        v.setMitigation(mitigation);
        v.setCweReference(cwe);
        v.setOwasp(owasp);
        v.setEvidenceMode(evidenceMode);
        
        String folder = "uploads/" + p.getId() + "/" + UUID.randomUUID().toString();
        v.setPocFolderPath(folder);

        if (steps != null) {
            for (VulnerabilityStep s : steps) {
                s.setVulnerability(v);
                v.getSteps().add(s);
                if (s.getImagePaths() != null) {
                    for (String img : s.getImagePaths()) {
                        copyPocImage(v.getPocFolderPath(), img);
                    }
                }
            }
        }
        vulnerabilityRepository.save(v);
    }

    private VulnerabilityStep createStep(int num, String desc, String req, String res, String... images) {
        VulnerabilityStep s = new VulnerabilityStep();
        s.setStepNumber(num);
        s.setDescription(desc);
        s.setRequest(req);
        s.setResponse(res);
        if (images != null && images.length > 0) {
            s.setImagePaths(new ArrayList<>(Arrays.asList(images)));
        }
        return s;
    }

    // --- POPULATION METHODS ---

    private void populateFintechVulns(Pentest p) {
        addVuln(p, "SQL Injection in Transaction Search", "CRITICAL", 9.8, "Open", "Approved", "Active",
            "The search parameter in the transaction history module is vulnerable to SQL injection.",
            "Complete database takeover and financial data exfiltration.",
            "Use parameterized queries or ORM for all database interactions.",
            "CWE-89", "A03:2021-Injection", "STEPS", List.of(
                createStep(1, "Navigate to /api/transactions/search", "GET /api/transactions/search?query=' OR 1=1--", "HTTP/2 200 OK\n[Full transaction list returned]", "Web.png"),
                createStep(2, "Extract database version using UNION SELECT", "GET /api/transactions/search?query=' UNION SELECT @@version,NULL--", "HTTP/2 200 OK\n[version: PostgreSQL 14.2]", "Web.png")
            ));

        addVuln(p, "Stored Cross-Site Scripting (XSS) in User Profile", "HIGH", 8.1, "Open", "Approved", "Active",
            "The user profile bio field does not properly sanitize input, allowing for stored XSS.",
            "Session hijacking and account takeover of other users viewing the profile.",
            "Implement robust output encoding and CSP headers.",
            "CWE-79", "A03:2021-Injection", "STEPS", List.of(
                createStep(1, "Update bio with payload", "POST /api/profile/update\n{\"bio\": \"<script>alert(document.cookie)</script>\"}", "HTTP/2 200 OK", "Web.png"),
                createStep(2, "Visit profile page to trigger payload", "N/A", "Script executes in browser context", "Web.png")
            ));

        addVuln(p, "Insecure Direct Object Reference (IDOR) in Statement Download", "HIGH", 7.5, "Open", "Approved", "Active",
            "Users can download statements belonging to other accounts by modifying the statement ID.",
            "Unauthorized access to sensitive financial statements of other users.",
            "Implement server-side authorization checks for every request.",
            "CWE-639", "A01:2021-Broken Access Control", "STEPS", List.of(
                createStep(1, "Log in as User A and view statement ID 105", "GET /api/statements/105", "HTTP/2 200 OK", "Web.png"),
                createStep(2, "Log in as User B and request statement ID 105", "GET /api/statements/105", "HTTP/2 200 OK [Downloaded User A's statement]", "Web.png")
            ));

        addVuln(p, "Cross-Site Request Forgery (CSRF) on Fund Transfer", "MEDIUM", 6.5, "Open", "Active", "Pending Approval",
            "The fund transfer endpoint lacks CSRF protection, allowing attackers to perform transfers on behalf of users.",
            "Unauthorized financial transactions via malicious websites.",
            "Implement Anti-CSRF tokens and SameSite cookie attributes.",
            "CWE-352", "A01:2021-Broken Access Control", "STEPS", List.of(
                createStep(1, "Host malicious HTML form", "<form action='https://banking.com/transfer' method='POST'>...", "N/A", "Web.png"),
                createStep(2, "User visits site and form auto-submits", "POST /transfer HTTP/1.1", "HTTP/2 302 Found [Transfer Success]", "Web.png")
            ));

        addVuln(p, "Lack of Rate Limiting on Login Endpoint", "MEDIUM", 5.3, "Open", "Active", "Pending Approval",
            "The login endpoint does not implement rate limiting, making it vulnerable to brute force attacks.",
            "Account takeover via automated credential stuffing.",
            "Implement account lockout and IP-based rate limiting.",
            "CWE-307", "A07:2021-Identification and Authentication Failures", "STEPS", List.of(
                createStep(1, "Submit 100 login requests in 5 seconds", "POST /api/auth/login", "HTTP/2 401 Unauthorized [No block]", "Web.png")
            ));

        addVuln(p, "Sensitive Data in URL Query String", "LOW", 3.7, "Open", "Active", "Pending Approval",
            "The application passes session identifiers in the URL query string.",
            "Exposure of session tokens in browser history, logs, and referrer headers.",
            "Pass sensitive tokens only in the request body or secure headers.",
            "CWE-598", "A04:2021-Insecure Design", "STEPS", List.of(
                createStep(1, "Observe URL after login", "N/A", "https://banking.com/dashboard?token=eyJhbGci...", "Web.png")
            ));

        addVuln(p, "Weak Password Policy Enforced", "LOW", 3.1, "Open", "Active", "Pending Approval",
            "The system allows passwords as short as 6 characters without complexity requirements.",
            "Increased risk of account compromise via simple dictionary attacks.",
            "Enforce NIST-compliant password policies (12+ chars, entropy check).",
            "CWE-521", "A07:2021-Identification and Authentication Failures", "STEPS", List.of(
                createStep(1, "Register with password '123456'", "POST /api/auth/register", "HTTP/2 201 Created", "Web.png")
            ));

        addVuln(p, "Missing HSTS Header", "INFO", 0.0, "Open", "Active", "Pending Approval",
            "The server does not include the Strict-Transport-Security header.",
            "Potential for SSL stripping attacks during the initial connection.",
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all responses.",
            "CWE-319", "A05:2021-Security Misconfiguration", "STEPS", List.of(
                createStep(1, "Inspect response headers", "curl -I https://banking.com", "HSTS header missing", "Web.png")
            ));
    }

    private void populateHealthVulns(Pentest p) {
        addVuln(p, "Insecure Local Storage of Health Metrics", "HIGH", 7.8, "Open", "Active", "Pending Approval",
            "Patient biometric data is stored unencrypted in the application's local database (SQLite).",
            "Privacy breach if the device is lost or compromised.",
            "Encrypt sensitive data using SQLCipher or Android Keystore.",
            "CWE-312", "M1: Insecure Data Storage", "STEPS", List.of(
                createStep(1, "Access app data directory on rooted device", "adb shell cat /data/data/com.biohealth/databases/metrics.db", "[Plaintext health data revealed]", "Mobile.png")
            ));

        addVuln(p, "SSL Pinning Not Implemented", "MEDIUM", 5.9, "Open", "Active", "Pending Approval",
            "The application trusts any certificate in the system store, facilitating MitM attacks.",
            "Interception and modification of sensitive health data during transit.",
            "Implement SSL Certificate Pinning to restrict trust to specific server certificates.",
            "CWE-295", "M3: Insecure Communication", "STEPS", List.of(
                createStep(1, "Install Burp CA on device and intercept traffic", "N/A", "Traffic successfully decrypted in Burp", "Mobile.png")
            ));

        addVuln(p, "Hardcoded Firebase API Key with Over-privileged Access", "MEDIUM", 6.2, "Open", "Active", "Pending Approval",
            "The Firebase API key in the APK allows read/write access to all user records.",
            "Mass data exposure and unauthorized modification of health records.",
            "Restrict Firebase API key permissions and use environment-specific configs.",
            "CWE-798", "M2: Insecure Authorization", "STEPS", List.of(
                createStep(1, "Decompile APK and find API key in strings.xml", "N/A", "<string name='google_api_key'>AIzaSy...</string>", "Mobile.png"),
                createStep(2, "Use key to query Firebase REST API", "GET https://firestore.googleapis.com/v1/projects/...", "200 OK [All records returned]", "Mobile.png")
            ));

        addVuln(p, "Broken Biometric Authentication (FaceID/TouchID)", "HIGH", 7.2, "Open", "Active", "Pending Approval",
            "The app uses a boolean flag from the biometric API that can be easily hooked and bypassed.",
            "Unauthorized access to the app by bypassing biometric checks.",
            "Use cryptographic signatures (CryptoObject) tied to the biometric event.",
            "CWE-287", "M4: Insecure Authentication", "STEPS", List.of(
                createStep(1, "Use Frida to hook biometric authentication result", "N/A", "Authentication bypassed without valid biometric input", "Mobile.png")
            ));

        addVuln(p, "Information Leakage via Android Logs", "LOW", 3.2, "Open", "Active", "Pending Approval",
            "The app logs sensitive user session tokens and email addresses to Logcat.",
            "Tokens can be read by other apps with log reading permissions (pre-Android 13) or via ADB.",
            "Disable debug logging in production builds and remove sensitive info from logs.",
            "CWE-532", "M1: Insecure Data Storage", "STEPS", List.of(
                createStep(1, "Monitor logs during login", "adb logcat", "DEBUG: Auth Token: eyJhbGci...", "Mobile.png")
            ));

        addVuln(p, "No Root/Jailbreak Detection", "LOW", 2.1, "Open", "Active", "Pending Approval",
            "The application does not check if it is running on a compromised device.",
            "Increased risk of attack as runtime security features are disabled on rooted devices.",
            "Implement root detection checks and warn or block the user.",
            "CWE-919", "M8: Code Tampering", "STEPS", List.of(
                createStep(1, "Run app on rooted emulator", "N/A", "App runs without any warning", "Mobile.png")
            ));

        addVuln(p, "Insecure Deep Link Handling", "MEDIUM", 5.4, "Open", "Active", "Pending Approval",
            "Deep links can be used to trigger internal app actions without authentication.",
            "Potential for unauthorized data modification or account takeovers via malicious links.",
            "Validate all parameters in deep links and ensure user is authenticated.",
            "CWE-939", "M6: Insecure Authorization", "STEPS", List.of(
                createStep(1, "Trigger deep link via browser", "biohealth://settings/update?email=attacker@site.com", "Email updated without password check", "Mobile.png")
            ));

        addVuln(p, "Excessive App Permissions", "INFO", 0.0, "Open", "Active", "Pending Approval",
            "The app requests access to Bluetooth and Contacts which are not used for core features.",
            "Privacy concerns and potential for future misuse if the app is compromised.",
            "Remove unused permissions from AndroidManifest.xml and Info.plist.",
            "CWE-267", "M10: Extraneous Functionality", "STEPS", List.of(
                createStep(1, "Review manifest file", "N/A", "<uses-permission android:name='android.permission.BLUETOOTH' />", "Mobile.png")
            ));
    }

    private void populateLogisticsVulns(Pentest p) {
        addVuln(p, "BOLA: Broken Object Level Authorization in Shipment Lookup", "CRITICAL", 9.1, "Open", "Active", "Pending Approval",
            "Shipment details can be retrieved by any authenticated user by changing the shipment UUID in the URL.",
            "Unauthorized disclosure of client shipments, addresses, and tracking data.",
            "Verify that the shipment belongs to the authenticated user's organization.",
            "CWE-285", "API1:2023 - Broken Object Level Authorization", "STEPS", List.of(
                createStep(1, "Login and view shipment UUID A", "GET /api/v1/shipments/550e8400-e29b-41d4-a716-446655440000", "200 OK", "API.png"),
                createStep(2, "Request shipment UUID B (not owned)", "GET /api/v1/shipments/660f9511-f30c-52e5-b827-557766551111", "200 OK [Data returned]", "API.png")
            ));

        addVuln(p, "Mass Assignment in User Profile Update", "HIGH", 7.7, "Open", "Active", "Pending Approval",
            "The profile update endpoint allows users to set the 'role' field in the JSON request body.",
            "Elevation of privilege by promoting regular users to 'admin' role.",
            "Use Data Transfer Objects (DTOs) and allowlist fields for updates.",
            "CWE-915", "API6:2023 - Unrestricted Resource Consumption", "STEPS", List.of(
                createStep(1, "Submit update with role=admin", "PATCH /api/v1/profile\n{\"firstName\": \"Joe\", \"role\": \"admin\"}", "200 OK [User is now admin]", "API.png")
            ));

        addVuln(p, "Lack of Resources & Rate Limiting (Pagination Attack)", "MEDIUM", 6.3, "Open", "Active", "Pending Approval",
            "The list shipments endpoint allows a 'limit' parameter up to 1,000,000.",
            "Denial of Service (DoS) due to high database load and memory consumption.",
            "Enforce a maximum limit for pagination and implement rate limiting.",
            "CWE-770", "API4:2023 - Unrestricted Resource Consumption", "STEPS", List.of(
                createStep(1, "Request shipments with huge limit", "GET /api/v1/shipments?limit=1000000", "504 Gateway Timeout [Server crash]", "API.png")
            ));

        addVuln(p, "Broken Function Level Authorization in Admin Export", "HIGH", 8.4, "Open", "Active", "Pending Approval",
            "The admin-only CSV export endpoint is accessible to regular users who know the URL.",
            "Unauthorized mass export of entire logistics database.",
            "Implement RBAC checks at the function/controller level.",
            "CWE-285", "API5:2023 - Broken Function Level Authorization", "STEPS", List.of(
                createStep(1, "Access admin export as regular user", "GET /api/v1/admin/export-all", "200 OK [CSV download started]", "API.png")
            ));

        addVuln(p, "JWT Weak Secret Key", "CRITICAL", 9.4, "Open", "Active", "Pending Approval",
            "The application uses 'secret' as the HMAC-SHA256 signing key for JWTs.",
            "Attacker can forge valid JWTs and impersonate any user, including admin.",
            "Use a strong, randomly generated secret stored in a vault/environment variable.",
            "CWE-345", "API2:2023 - Broken Authentication", "STEPS", List.of(
                createStep(1, "Crack JWT with dictionary attack", "hashcat -m 16500 token.txt rockyou.txt", "Found: secret", "API.png")
            ));

        addVuln(p, "Information Disclosure via Stack Traces", "LOW", 3.1, "Open", "Active", "Pending Approval",
            "The API returns full stack traces in 500 Internal Server Error responses.",
            "Disclosure of internal file paths, library versions, and database structure.",
            "Implement a global error handler that returns generic error messages.",
            "CWE-209", "API7:2023 - Server Side Request Forgery", "STEPS", List.of(
                createStep(1, "Send malformed JSON", "POST /api/v1/shipments\n{invalid}", "500 Internal Server Error [Full trace]", "API.png")
            ));

        addVuln(p, "Unprotected API Endpoint (Health Check)", "LOW", 2.5, "Open", "Active", "Pending Approval",
            "The /health endpoint returns detailed system stats without authentication.",
            "Reconnaissance for infrastructure details (CPU, memory, uptime).",
            "Require authentication for all non-public endpoints or restrict by IP.",
            "CWE-200", "API5:2023 - Broken Function Level Authorization", "STEPS", List.of(
                createStep(1, "Query health endpoint", "GET /health", "200 OK [System details revealed]", "API.png")
            ));

        addVuln(p, "Broken Property Level Authorization (Internal IDs)", "MEDIUM", 4.8, "Open", "Active", "Pending Approval",
            "The shipment response includes internal database IDs and creator email addresses.",
            "Disclosure of internal data structures and potential for social engineering.",
            "Filter sensitive fields from the API response at the serialization layer.",
            "CWE-212", "API3:2023 - Broken Object Property Level Authorization", "STEPS", List.of(
                createStep(1, "View shipment details", "GET /api/v1/shipments/UUID", "200 OK [\"_creatorEmail\": \"admin@logistics.io\"]", "API.png")
            ));
    }

    private void populateInfraVulns(Pentest p) {
        addVuln(p, "Default Credentials on Web Management Interface", "CRITICAL", 10.0, "Open", "Active", "Pending Approval",
            "The internal network switch (10.50.0.1) uses default credentials (admin/admin).",
            "Full control over network traffic, VLANs, and potential traffic mirroring.",
            "Change all default credentials and disable web management if not needed.",
            "CWE-1392", "Default Config", "STEPS", List.of(
                createStep(1, "Navigate to 10.50.0.1 and login with admin/admin", "N/A", "Access granted to admin console", "Infra.png")
            ));

        addVuln(p, "Unpatched Windows Server 2022 (CVE-2024-21338)", "HIGH", 8.8, "Open", "Active", "Pending Approval",
            "The domain controller is missing critical security updates for kernel privilege escalation.",
            "Local privilege escalation from regular user to SYSTEM.",
            "Install all pending Windows security updates immediately.",
            "CWE-264", "Vulnerable Software", "STEPS", List.of(
                createStep(1, "Verify patch level on 10.50.0.10", "systeminfo", "[KB####### missing]", "Infra.png")
            ));

        addVuln(p, "Weak SSH Configuration (CBC Ciphers)", "MEDIUM", 5.4, "Open", "Active", "Pending Approval",
            "The Linux file server (172.16.10.5) supports weak CBC encryption ciphers.",
            "Susceptibility to plaintext recovery attacks (e.g., Terrier, SSH-SPA).",
            "Disable CBC ciphers and enable strong GCM or Chacha20-Poly1305 ciphers.",
            "CWE-327", "Weak Crypto", "STEPS", List.of(
                createStep(1, "Scan SSH ciphers", "ssh-audit 172.16.10.5", "[aes128-cbc, 3des-cbc enabled]", "Infra.png")
            ));

        addVuln(p, "Open SMB Shares with Anonymous Access", "HIGH", 7.5, "Open", "Active", "Pending Approval",
            "The 'Public' share on the file server allows anonymous read/write access.",
            "Unauthorized access to shared documents and potential malware distribution point.",
            "Disable anonymous access and enforce authenticated SMB sessions.",
            "CWE-16", "Insecure Config", "STEPS", List.of(
                createStep(1, "List shares anonymously", "smbclient -L 172.16.10.5 -N", "[Public] read/write", "Infra.png")
            ));

        addVuln(p, "Anonymous FTP Access Enabled", "MEDIUM", 4.3, "Open", "Active", "Pending Approval",
            "The printer server (10.50.0.50) has an FTP server with anonymous login enabled.",
            "Potential disclosure of print jobs and configuration data.",
            "Disable anonymous FTP and move to SFTP if file transfer is required.",
            "CWE-287", "Insecure Config", "STEPS", List.of(
                createStep(1, "Login as anonymous", "ftp 10.50.0.50", "230 Login successful", "Infra.png")
            ));

        addVuln(p, "SSL/TLS Weak Ciphers (DES/RC4)", "MEDIUM", 5.0, "Open", "Active", "Pending Approval",
            "The internal intranet site (172.16.10.2) supports legacy DES and RC4 ciphers.",
            "Traffic can be decrypted by attackers with moderate computational power.",
            "Disable all legacy ciphers and support only TLS 1.2/1.3 with AEAD ciphers.",
            "CWE-326", "Weak Crypto", "STEPS", List.of(
                createStep(1, "Scan TLS protocols", "sslscan 172.16.10.2", "[Accepted: TLSv1.0 RC4-SHA]", "Infra.png")
            ));

        addVuln(p, "DNS Zone Transfer (AXFR) Possible", "LOW", 3.3, "Open", "Active", "Pending Approval",
            "The internal DNS server allows AXFR zone transfers from any IP address.",
            "Full map of internal hostnames and IP addresses disclosed to attackers.",
            "Restrict zone transfers to specific secondary DNS server IPs.",
            "CWE-16", "Reconnaissance", "STEPS", List.of(
                createStep(1, "Perform zone transfer", "dig axfr @10.50.0.2 corp.apex.internal", "[Full list of hosts]", "Infra.png")
            ));

        addVuln(p, "ICMP Echo Requests Enabled on External Interface", "INFO", 0.0, "Open", "Active", "Pending Approval",
            "The DMZ firewall responds to ICMP echo requests (ping).",
            "Easier reconnaissance for active hosts in the DMZ.",
            "Disable ICMP responses on external-facing interfaces.",
            "CWE-200", "Reconnaissance", "STEPS", List.of(
                createStep(1, "Ping firewall", "ping 45.76.12.11", "64 bytes from 45.76.12.11...", "Infra.png")
            ));
    }

    private void populateSourceVulns(Pentest p) {
        addVuln(p, "Hardcoded Database Credentials", "CRITICAL", 9.8, "Open", "Active", "Pending Approval",
            "The application properties file contains plaintext database credentials.",
            "Full database access if the source code is compromised or leaked.",
            "Use environment variables or a vault service for credential management.",
            "CWE-798", "A07:2021-Identification and Authentication Failures", "SOURCE", List.of(
                createStep(1, "Found in application.properties", "spring.datasource.password=SecurePass123!", "N/A", "CodeReview4.png")
            ));

        addVuln(p, "Use of Insecure Cryptography (MD5 for Passwords)", "CRITICAL", 9.1, "Open", "Active", "Pending Approval",
            "The CustomPasswordEncoder.java class uses MD5 for hashing passwords.",
            "Passwords can be easily cracked via rainbow tables and brute force.",
            "Use Argon2, BCrypt (cost > 12), or SCrypt for password hashing.",
            "CWE-327", "A02:2021-Cryptographic Failures", "SOURCE", List.of(
                createStep(1, "Review CustomPasswordEncoder.java", "MessageDigest.getInstance(\"MD5\")", "N/A", "CodeReview4.png")
            ));

        addVuln(p, "Path Traversal in File Upload Service", "HIGH", 8.8, "Open", "Active", "Pending Approval",
            "The FileService.java class does not sanitize filenames, allowing path traversal.",
            "Arbitrary file write/overwrite outside the intended upload directory.",
            "Sanitize filenames and use a fixed base directory with path normalization.",
            "CWE-22", "A03:2021-Injection", "SOURCE", List.of(
                createStep(1, "Review FileService.java", "new File(uploadDir + \"/\" + fileName)", "N/A", "CodeReview4.png")
            ));

        addVuln(p, "Null Pointer Dereference in Token Validation", "MEDIUM", 5.7, "Open", "Active", "Pending Approval",
            "The JWT filter does not check if the 'sub' claim is present before processing.",
            "Potential for service disruption (DoS) via crafted tokens.",
            "Implement null checks and robust validation for all token claims.",
            "CWE-476", "Robustness", "SOURCE", List.of(
                createStep(1, "Review JwtFilter.java", "String sub = claims.getSubject(); if (sub.equals(...))", "N/A", "CodeReview4.png")
            ));

        addVuln(p, "Insecure Randomness (java.util.Random)", "LOW", 3.2, "Open", "Active", "Pending Approval",
            "The password reset token generator uses java.util.Random instead of SecureRandom.",
            "Predicted reset tokens allowing for unauthorized password changes.",
            "Use java.security.SecureRandom for all security-sensitive random values.",
            "CWE-338", "A02:2021-Cryptographic Failures", "SOURCE", List.of(
                createStep(1, "Review TokenUtils.java", "Random rnd = new Random();", "N/A", "CodeReview4.png")
            ));

        addVuln(p, "Improper Exception Handling (Leaking Sensitive Info)", "LOW", 2.1, "Open", "Active", "Pending Approval",
            "Catch blocks print the full exception to System.out and return it to the UI.",
            "Internal technical details revealed to users.",
            "Log exceptions using a logging framework and return generic error codes.",
            "CWE-209", "A04:2021-Insecure Design", "SOURCE", List.of(
                createStep(1, "Review GlobalHandler.java", "e.printStackTrace(); return e.getMessage();", "N/A", "CodeReview4.png")
            ));

        addVuln(p, "Hardcoded Internal IP Addresses", "INFO", 0.0, "Open", "Active", "Pending Approval",
            "Several classes contain hardcoded internal IP addresses for service calls.",
            "Difficulty in maintenance and disclosure of internal network topology.",
            "Move all service endpoints to configuration files or service discovery.",
            "CWE-200", "A04:2021-Insecure Design", "SOURCE", List.of(
                createStep(1, "Review Config.java", "private String legacyUrl = \"http://10.20.5.11:8080\";", "N/A", "CodeReview4.png")
            ));

        addVuln(p, "Use of Deprecated Cryptographic Library", "LOW", 2.8, "Open", "Active", "Pending Approval",
            "The project uses an old version of BouncyCastle with known vulnerabilities.",
            "Potential for exploitation of known flaws in the cryptographic library.",
            "Update to the latest stable version of BouncyCastle.",
            "CWE-1104", "A06:2021-Vulnerable and Outdated Components", "SOURCE", List.of(
                createStep(1, "Review pom.xml", "<version>1.46</version>", "N/A", "CodeReview4.png")
            ));
    }

    private void populateHRVulns(Pentest p) {
        // Shorter set for HR
        addVuln(p, "Unauthenticated Access to Salary Records", "CRITICAL", 9.9, "Open", "Active", "Pending Approval",
            "The /export/salary endpoint can be accessed without any session token.",
            "Massive privacy breach and disclosure of confidential payroll data.",
            "Apply authentication filters to all sensitive endpoints.",
            "CWE-284", "A01:2021-Broken Access Control", "STEPS", List.of(
                createStep(1, "Access export URL directly", "GET /export/salary", "200 OK [CSV with all salaries]", "Web.png")
            ));

        addVuln(p, "Stored XSS in Employee Feedback Form", "HIGH", 8.2, "Open", "Active", "Pending Approval",
            "Feedback submitted by employees is rendered in the admin dashboard without encoding.",
            "Session hijacking of HR administrators.",
            "Encode all user-generated content before rendering.",
            "CWE-79", "A03:2021-Injection", "STEPS", List.of(
                createStep(1, "Submit feedback with script", "<img src=x onerror=alert(1)>", "200 OK", "Web.png")
            ));

        addVuln(p, "Weak Session Management (Long Duration)", "MEDIUM", 4.5, "Open", "Active", "Pending Approval",
            "Sessions remain valid for 30 days without activity.",
            "Increased window of opportunity for session hijacking.",
            "Reduce session timeout to a reasonable duration (e.g., 8 hours).",
            "CWE-613", "A07:2021-Identification and Authentication Failures", "STEPS", List.of(
                createStep(1, "Check session cookie expiry", "N/A", "Max-Age=2592000", "Web.png")
            ));

        addVuln(p, "Information Disclosure via .env File", "HIGH", 7.4, "Open", "Active", "Pending Approval",
            "The .env file is accessible via the web server due to misconfiguration.",
            "Exposure of database credentials and API keys.",
            "Restrict access to sensitive files at the web server level.",
            "CWE-552", "A05:2021-Security Misconfiguration", "STEPS", List.of(
                createStep(1, "Request .env file", "GET /.env", "200 OK [DB_PASSWORD=...]", "Web.png")
            ));
            
        addVuln(p, "Open Redirect on Login Redirect", "LOW", 3.8, "Open", "Active", "Pending Approval",
            "The 'next' parameter in the login URL is not validated.",
            "Facilitates phishing attacks by redirecting users to malicious sites.",
            "Validate redirect URLs against a whitelist of allowed domains.",
            "CWE-601", "A04:2021-Insecure Design", "STEPS", List.of(
                createStep(1, "Click malicious link", "/login?next=http://malicious.com", "302 Redirect to malicious.com", "Web.png")
            ));
    }

    private void initializeOrganization() {
        if (organizationRepository.count() == 0) {
            Organization org = new Organization();
            org.setName("VulnPrint Security Services");
            org.setLegalName("VulnPrint Cyber Solutions Ltd.");
            org.setAddress("123 Terminal Elite Tower, Neon District, Cyber City");
            org.setPhone("+1-555-VULN-PRT");
            org.setEmail("security@vulnprint.io");
            organizationRepository.save(org);
        }
    }

    @Autowired
    private PermissionRepository permissionRepository;

    @Autowired
    private org.springframework.core.io.ResourceLoader resourceLoader;

    private void copyPocImage(String folder, String imageName) {
        try {
            java.nio.file.Path targetPath = java.nio.file.Paths.get(folder);
            if (!java.nio.file.Files.exists(targetPath)) {
                java.nio.file.Files.createDirectories(targetPath);
            }
            
            org.springframework.core.io.Resource resource = resourceLoader.getResource("classpath:static/images/Methodologies/" + imageName);
            if (resource.exists()) {
                java.nio.file.Files.copy(resource.getInputStream(), targetPath.resolve(imageName), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (Exception e) {
            System.err.println("[SYSTEM] Failed to copy POC image: " + imageName + " - " + e.getMessage());
        }
    }

    private Role initializePentesterRole() {
        Role role = roleRepository.findByName("Penetration Tester").orElseGet(() -> new Role("Penetration Tester"));
        Set<String> perms = Set.of(
            AppSecurityGuard.VIEW_DASHBOARD, AppSecurityGuard.VIEW_ALERTS,
            AppSecurityGuard.VIEW_ASSIGNED_PROJECTS, AppSecurityGuard.EDIT_ASSIGNED_PROJECTS,
            AppSecurityGuard.ADD_VULNERABILITY, AppSecurityGuard.VIEW_ASSIGNED_VULNS, 
            AppSecurityGuard.EDIT_ASSIGNED_VULNS, AppSecurityGuard.CHANGE_VULN_REPORTING_STATUS,
            AppSecurityGuard.CHANGE_VULN_STATUS, AppSecurityGuard.EDIT_MY_PROFILE
        );
        role.setPermissions(new HashSet<>(permissionRepository.findByNameIn(perms)));
        return roleRepository.save(role);
    }

    private Role initializeAuditorRole() {
        Role role = roleRepository.findByName("Auditor").orElseGet(() -> new Role("Auditor"));
        Set<String> perms = Set.of(
            AppSecurityGuard.VIEW_DASHBOARD, AppSecurityGuard.VIEW_ALERTS,
            AppSecurityGuard.VIEW_ALL_PROJECTS, AppSecurityGuard.VIEW_ALL_VULNS,
            AppSecurityGuard.VIEW_USERS, AppSecurityGuard.EDIT_MY_PROFILE,
            AppSecurityGuard.ENABLE_2FA
        );
        role.setPermissions(new HashSet<>(permissionRepository.findByNameIn(perms)));
        return roleRepository.save(role);
    }
}
