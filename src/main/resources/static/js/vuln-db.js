const vulnerabilityDatabase = [
    {
        "name": "Server-Side Template Injection (SSTI)",
        "type": "Web",
        "cwe": "CWE-1336",
        "owasp": "A03:2021-Injection",
        "description": "The application unsafely embeds user-controlled data directly into server-side templates (e.g., Jinja2, Freemarker).",
        "impact": "Direct escalation to Remote Code Execution (RCE), complete server compromise, and exfiltration of environment variables.",
        "mitigation": [
            "Pass user input to templates exclusively as data context, never as raw template strings.",
            "Utilize 'logic-less' template engines.",
            "Execute dynamic template rendering in a strict sandbox.",
            "Sanitize input to strip template-specific syntax.",
            "Keep template libraries updated.",
            "Regularly audit dynamic template generation endpoints."
        ],
        "is_foundational": true
    },
    {
        "name": "HTTP Parameter Pollution (HPP)",
        "type": "Web",
        "cwe": "CWE-235",
        "owasp": "A03:2021-Injection",
        "description": "The application is sent multiple HTTP parameters with the same name (e.g., `?id=1&id=2`). Depending on the backend technology, it may parse the first, the last, or an array of both, creating a discrepancy between WAF validation and backend processing logic.",
        "impact": "Bypass of Web Application Firewalls (WAFs), overriding of critical parameters (like account IDs or action flags), and subversion of business logic.",
        "mitigation": [
            "Ensure the application strictly rejects requests containing duplicate parameters if not explicitly expected.",
            "Use frameworks that parse parameters predictably and securely.",
            "If duplicate parameters are expected (e.g., arrays), validate every element of the array individually.",
            "Ensure WAF rules parse parameters in the exact same manner as the backend application (preventing impedance mismatch).",
            "Implement robust input validation and type checking.",
            "Conduct fuzzing focused on parameter duplication."
        ],
        "is_foundational": true
    },
    {
        "name": "Insecure Deserialization (.NET BinaryFormatter)",
        "type": "Web",
        "cwe": "CWE-502",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "description": "The .NET application utilizes insecure serializers like `BinaryFormatter`, `NetDataContractSerializer`, or `LosFormatter` to process untrusted input. Attackers craft payloads utilizing known .NET gadget chains (e.g., TypeConfuseDelegate) to execute code.",
        "impact": "Direct escalation to Remote Code Execution (RCE) on the Windows/Linux host running the .NET runtime.",
        "mitigation": [
            "Eradicate the use of `BinaryFormatter` and similar legacy serializers across the entire codebase.",
            "Transition to secure alternatives like `System.Text.Json` or `DataContractSerializer` configured safely.",
            "Implement a strict `SerializationBinder` to explicitly allowlist permitted types during deserialization.",
            "Cryptographically protect serialized payloads using ASP.NET Data Protection APIs if transmission is necessary.",
            "Audit third-party libraries for insecure serialization practices.",
            "Ensure the .NET runtime is fully patched against known gadget chains."
        ],
        "is_foundational": true
    },
    {
        "name": "Error-Based SQL Injection",
        "type": "Web",
        "cwe": "CWE-89",
        "owasp": "A03:2021-Injection",
        "description": "The application constructs dynamic queries using unsanitized input, causing the database to leak structure and data through verbose error messages.",
        "impact": "Full database extraction, authentication bypass, and potential Remote Code Execution (RCE).",
        "mitigation": [
            "Use Prepared Statements and Parameterized Queries exclusively.",
            "Disable verbose database errors in production environments.",
            "Implement a secure ORM layer for all data interactions.",
            "Enforce the principle of least privilege for the DB user.",
            "Sanitize all inputs against strict allowlists.",
            "Deploy a WAF to block common SQLi payloads."
        ],
        "is_foundational": true
    },
    {
        "name": "DOM-Based Cross-Site Scripting (XSS)",
        "type": "Web",
        "cwe": "CWE-79",
        "owasp": "A03:2021-Injection",
        "description": "Malicious scripts are executed entirely within the browser's Document Object Model (DOM) by passing untrusted data from a source (like window.location) to a dangerous sink (like eval()).",
        "impact": "Client-side data theft and session hijacking that is often invisible to server-side security logs.",
        "mitigation": [
            "Avoid dangerous sinks like innerHTML, outerHTML, and eval().",
            "Prefer safe methods like textContent or innerText.",
            "Sanitize untrusted data on the client side before rendering.",
            "Utilize CSP to restrict script execution environments.",
            "Perform automated SAST on all client-side JavaScript.",
            "Review JS logic that processes URL fragments or query params."
        ],
        "is_foundational": true
    },
    {
        "name": "Server-Side Request Forgery (SSRF) via Cloud Metadata",
        "type": "Web",
        "cwe": "CWE-918",
        "owasp": "A10:2021-SSRF",
        "description": "The application fetches remote resources via user-supplied URLs. Hosted in AWS/GCP/Azure, an attacker supplies the metadata IP (e.g., 169.254.169.254) to extract instance credentials.",
        "impact": "Total cloud environment compromise by stealing temporary IAM credentials attached to the compute instance.",
        "mitigation": [
            "Enforce IMDSv2 on AWS, requiring a PUT request session token.",
            "Implement a strict network allowlist for outbound HTTP requests.",
            "Block access to 169.254.169.254 via host-level iptables for non-root users.",
            "Ensure IAM roles attached to instances follow absolute least privilege.",
            "Run fetching logic in an isolated VPC subnet.",
            "Monitor CloudTrail for anomalous credential usage."
        ],
        "is_foundational": true
    },
    {
        "name": "Reflected Cross-Site Scripting (XSS)",
        "type": "Web",
        "cwe": "CWE-79",
        "owasp": "A03:2021-Injection",
        "description": "The application immediately echoes unvalidated user input back into the HTTP response. Attackers craft malicious URLs to execute scripts in the victim's session.",
        "impact": "Facilitates targeted phishing, session theft, and unauthorized user actions via social engineering.",
        "mitigation": [
            "Ensure all reflected data is HTML entity-encoded.",
            "Implement a strong CSP.",
            "Avoid placing user input into executable DOM contexts.",
            "Validate URL parameters against expected formats.",
            "Use secure, built-in framework features for reflection.",
            "Regularly scan for reflected injection points."
        ],
        "is_foundational": true
    },
    {
        "name": "Stored Cross-Site Scripting (XSS)",
        "type": "Web",
        "cwe": "CWE-79",
        "owasp": "A03:2021-Injection",
        "description": "The application fails to sanitize user input before storing it in the database. When the data is later retrieved and rendered, malicious scripts execute in the browser of any user viewing the content.",
        "impact": "Persistent session hijacking, unauthorized actions on behalf of users, and potential administrative account compromise.",
        "mitigation": [
            "Implement context-aware output encoding.",
            "Enforce a robust Content Security Policy (CSP).",
            "Sanitize input using DOMPurify.",
            "Use modern frameworks that encode data by default.",
            "Set HttpOnly and Secure flags on session cookies.",
            "Validate input against a strict allowlist of characters."
        ],
        "is_foundational": true
    },
    {
        "name": "Android Task Hijacking (StrandHogg)",
        "type": "Mobile",
        "cwe": "CWE-1021",
        "owasp": "M1:2023-Improper Platform Usage",
        "description": "The application suffers from improper task affinity configuration (e.g., `taskAffinity` combined with `allowTaskReparenting`). A malicious application can insert its own malicious Activity into the vulnerable application's task stack.",
        "impact": "Highly deceptive UI spoofing (Tapjacking/Phishing) where the user believes they are interacting with the legitimate app, leading to the theft of credentials and MFA codes.",
        "mitigation": [
            "Explicitly set `android:taskAffinity=\"\"` (empty string) for sensitive Activities to prevent them from associating with other tasks.",
            "Set `android:allowTaskReparenting=\"false\"` to prevent Activities from moving between tasks.",
            "Use the `FLAG_ACTIVITY_NEW_TASK` and `FLAG_ACTIVITY_CLEAR_TASK` flags appropriately when launching critical flows.",
            "Implement strong visual branding and potentially mutual authentication for critical UI transitions.",
            "Stay updated with Android OS security patches that mitigate OS-level task hijacking vectors.",
            "Audit the AndroidManifest.xml for dangerous task management configurations."
        ],
        "is_foundational": true
    },
    {
        "name": "Unsafe Consumption of Third-Party APIs (SSRF via Webhook)",
        "type": "API",
        "cwe": "CWE-918",
        "owasp": "API10:2023-Unsafe Consumption of APIs",
        "description": "The API integrates with a third-party service by accepting Webhook URLs provided by the user. The application blindly trusts this URL and makes subsequent HTTP requests (callbacks) to it without enforcing network boundary restrictions.",
        "impact": "Attackers can supply internal IPs or cloud metadata endpoints, forcing the API to execute Server-Side Request Forgery (SSRF) and extract highly sensitive internal infrastructure data.",
        "mitigation": [
            "Implement a rigorous, strict allowlist of permitted IP ranges and domains for all outbound Webhook requests.",
            "Explicitly block outbound connections to internal IP address spaces (RFC 1918) and cloud metadata services (e.g., 169.254.169.254).",
            "Resolve the DNS record of the provided URL and verify the resulting IP before initiating the HTTP connection (protecting against DNS rebinding).",
            "Run the Webhook dispatch service in a heavily restricted, isolated network segment.",
            "Enforce strict timeouts and rate limits on outbound requests.",
            "Avoid echoing the detailed HTTP response of the Webhook back to the user."
        ],
        "is_foundational": true
    },
    {
        "name": "API Security Misconfiguration (Verbose Stack Traces)",
        "type": "API",
        "cwe": "CWE-209",
        "owasp": "API8:2023-Security Misconfiguration",
        "description": "The API is misconfigured to return detailed, raw backend error messages, exception traces, and framework diagnostics to the client when an unexpected condition occurs (e.g., a database connection failure or malformed JSON).",
        "impact": "Information disclosure of internal library versions, file paths, database schemas, and architectural logic, providing attackers with the precise data needed to launch targeted exploits.",
        "mitigation": [
            "Implement centralized global exception handling within the API framework.",
            "Ensure all unhandled exceptions are caught and sanitized before the HTTP response is generated.",
            "Return generic, standardized JSON error messages (e.g., 'An unexpected error occurred') to the client.",
            "Log the detailed stack trace and forensic data securely to an internal, protected logging system.",
            "Audit API configurations to disable debug mode in production environments.",
            "Perform negative testing (fuzzing) to ensure the API fails gracefully under malformed input."
        ],
        "is_foundational": true
    },
    {
        "name": "Insecure Android Content Provider (SQLi / Path Traversal)",
        "type": "Mobile",
        "cwe": "CWE-926",
        "owasp": "M1:2023-Improper Platform Usage",
        "description": "The application exports a Content Provider to share data, but fails to implement proper permissions or input validation. This allows malicious apps to query the provider using SQL injection or perform path traversal to read internal app files.",
        "impact": "Extraction of the application's entire private SQLite database, theft of sensitive local files, and unauthorized data modification.",
        "mitigation": [
            "Ensure `android:exported=\"false\"` unless data sharing with external apps is explicitly required.",
            "If sharing is required, enforce strict `android:readPermission` and `android:writePermission`.",
            "Use parameterized queries within the Content Provider to thwart SQL injection.",
            "Validate and sanitize all file paths requested via the Content Provider to prevent traversal.",
            "Implement URI permissions (`grantUriPermissions`) to grant temporary, granular access instead of global access.",
            "Regularly audit the data exposure footprint of all Content Providers."
        ],
        "is_foundational": true
    },
    {
        "name": "Server-Side Includes (SSI) Injection",
        "type": "Web",
        "cwe": "CWE-97",
        "owasp": "A03:2021-Injection",
        "description": "The web server is configured to evaluate Server-Side Includes (SSI) directives in HTML files. An attacker injects SSI directives (e.g., `<!--#exec cmd=\"ls\" -->`) via a vulnerable input field, which are evaluated when the page is served.",
        "impact": "Immediate Remote Code Execution (RCE) granting the attacker control over the web server.",
        "mitigation": [
            "Disable Server-Side Includes (SSI) entirely in the web server configuration if they are not explicitly required.",
            "If SSI is necessary, disable the 'exec' directive to prevent command execution.",
            "HTML entity-encode all user input to ensure SSI directives are treated as plain text.",
            "Serve user-generated content from isolated domains where SSI processing is turned off.",
            "Ensure files containing user input do not use extensions associated with SSI (e.g., .shtml).",
            "Run the web server with least privilege."
        ],
        "is_foundational": true
    },
    {
        "name": "LFI to RCE via Log Poisoning",
        "type": "Web",
        "cwe": "CWE-98",
        "owasp": "A03:2021-Injection",
        "description": "The application suffers from Local File Inclusion. An attacker injects malicious executable code (e.g., PHP) into a local file the application writes to, such as an Apache/Nginx access log or an SSH log (via User-Agent or username), and then uses the LFI to include and execute that log file.",
        "impact": "Direct escalation from arbitrary file read to unauthenticated Remote Code Execution (RCE), leading to full server compromise.",
        "mitigation": [
            "Remediate the underlying Local File Inclusion (LFI) vulnerability.",
            "Ensure application server logs are stored outside the web root and are not readable by the application process.",
            "Disable dynamic code evaluation (like allow_url_include in PHP) entirely.",
            "Store logs on a centralized logging server rather than the local disk.",
            "Run the web application under a low-privilege user.",
            "Use WAFs to detect LFI patterns."
        ],
        "is_foundational": true
    },
    {
        "name": "CORS Misconfiguration (Trusting Null Origin)",
        "type": "Web",
        "cwe": "CWE-942",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "The CORS configuration explicitly allows the 'null' origin and sets Access-Control-Allow-Credentials to true. Attackers can generate requests with a 'null' origin using sandboxed iframes or data URLs.",
        "impact": "Bypasses the Same-Origin Policy, allowing attackers to execute cross-origin requests and steal sensitive, authenticated session data.",
        "mitigation": [
            "Never allow the 'null' origin in the Access-Control-Allow-Origin header.",
            "Maintain a strict, hardcoded allowlist of explicitly trusted domain strings.",
            "Do not dynamically reflect the incoming Origin header.",
            "Disable Access-Control-Allow-Credentials unless cross-origin authenticated requests are an absolute necessity.",
            "Audit API gateway and application framework CORS configurations.",
            "Monitor API traffic for requests originating from unexpected domains."
        ],
        "is_foundational": true
    },
    {
        "name": "API Excessive Data Exposure (PII Leakage)",
        "type": "API",
        "cwe": "CWE-213",
        "owasp": "API3:2023-Broken Object Property Level Authorization",
        "description": "The API endpoint returns the entire database object (including sensitive fields like SSNs, internal hashes, or administrative flags) to the client-side application. The application relies on the frontend code to filter out the sensitive data before displaying it to the user.",
        "impact": "Attackers can intercept the raw HTTP response using a proxy (like Burp Suite) to harvest massive amounts of sensitive Personal Identifiable Information (PII) and internal system data.",
        "mitigation": [
            "Never rely on the client-side application to filter sensitive data.",
            "Implement strict Data Transfer Objects (DTOs) on the backend to meticulously define exactly which fields are serialized and sent to the client.",
            "Enforce robust schema validation on all outbound API responses.",
            "Adopt GraphQL appropriately to allow clients to request only specific fields, but ensure the resolvers enforce field-level authorization.",
            "Conduct regular code reviews of serialization logic.",
            "Utilize automated DAST tools to analyze API response payloads for sensitive data patterns."
        ],
        "is_foundational": true
    },
    {
        "name": "API Improper Assets Management (Shadow/Zombie APIs)",
        "type": "API",
        "cwe": "CWE-1059",
        "owasp": "API9:2023-Improper Inventory Management",
        "description": "The organization fails to maintain an accurate inventory of deployed API endpoints. Deprecated (Zombie) endpoints (e.g., /api/v1/auth) or undocumented (Shadow) endpoints remain active in the production environment. These endpoints lack modern security controls, rate limiting, or proper authentication.",
        "impact": "Provides attackers with a 'soft underbelly' to bypass the robust security controls implemented on newer API versions, leading to unauthorized access, BOLA exploitation, or massive data breaches.",
        "mitigation": [
            "Maintain a continuously updated, comprehensive API inventory using OpenAPI/Swagger specifications.",
            "Implement automated API discovery tools integrating with the API Gateway to identify undocumented traffic.",
            "Enforce a strict deprecation lifecycle, completely removing or disabling old API versions within a set timeframe.",
            "Ensure all endpoints, regardless of version, require mandatory authentication and authorization checks.",
            "Route all API traffic through a centralized, monitored Web Application Firewall (WAF).",
            "Regularly conduct penetration testing specifically targeting legacy infrastructure."
        ],
        "is_foundational": true
    },
    {
        "name": "Insecure Biometric Implementation (Lack of Crypto Binding)",
        "type": "Mobile",
        "cwe": "CWE-287",
        "owasp": "M3:2023-Insecure Authentication/Authorization",
        "description": "The application implements biometric login (FaceID/TouchID/Fingerprint) by merely checking the boolean boolean response (True/False) returned by the local biometric API. It does not cryptographically bind the successful biometric event to a secure hardware token.",
        "impact": "Attackers with physical access and root/jailbreak privileges can easily hook the biometric API (e.g., using Frida) to forcefully return 'True', completely bypassing the biometric authentication layer.",
        "mitigation": [
            "Never rely on the simple boolean callback of biometric APIs for authentication.",
            "Implement cryptographic binding: upon successful biometric authentication, unlock a private key stored securely in the hardware Keystore/Keychain.",
            "Use this unlocked private key to sign a challenge from the backend server to cryptographically prove identity.",
            "Invalidate the cryptographic key if a new biometric identity (e.g., a new fingerprint) is enrolled on the OS.",
            "Ensure the backend strictly requires the cryptographically signed challenge.",
            "Use the latest Android `BiometricPrompt` and iOS `LocalAuthentication` APIs securely."
        ],
        "is_foundational": true
    },
    {
        "name": "Local File Inclusion (LFI) via Path Traversal",
        "type": "Web",
        "cwe": "CWE-22",
        "owasp": "A01:2021-Broken Access Control",
        "description": "The application uses unvalidated user input to dynamically construct file paths. By injecting dot-dot-slash (../) sequences, attackers navigate outside the intended web root to read arbitrary files on the local filesystem.",
        "impact": "Disclosure of highly sensitive local files (e.g., /etc/passwd, application source code, configuration files containing credentials).",
        "mitigation": [
            "Avoid passing user-supplied input directly into filesystem APIs.",
            "Utilize indirect object references (mapping a hash or ID to the file path).",
            "Strictly validate input against an explicit allowlist of permitted filenames.",
            "Normalize the path (resolving symbolic links and relative sequences) and verify it begins with the safe base directory.",
            "Run the application with minimal filesystem permissions.",
            "Deploy in a chroot jail or minimal container."
        ],
        "is_foundational": true
    },
    {
        "name": "Background App Screen Snapshot Leakage",
        "type": "Mobile",
        "cwe": "CWE-200",
        "owasp": "M2:2023-Inadequate Supply Chain Security",
        "description": "When the application is sent to the background, the operating system takes a snapshot of the current screen to display in the task switcher. The application fails to mask or hide sensitive views (like account balances or PII) before this snapshot occurs.",
        "impact": "Sensitive data is stored in the device's unencrypted cache directory, allowing malicious apps or individuals with physical access to extract the snapshot images and steal private information.",
        "mitigation": [
            "On Android, set the `FLAG_SECURE` flag on the application Window to prevent the OS from taking screenshots and masking the task switcher view.",
            "On iOS, implement the `applicationDidEnterBackground` lifecycle method to overlay a splash screen or blur the UI before the OS takes the snapshot.",
            "Minimize the display of highly sensitive information on screen where possible.",
            "Clear sensitive data fields dynamically when detecting app backgrounding.",
            "Regularly audit the device's cache directory during testing to ensure no sensitive screenshots are stored.",
            "Educate development teams on mobile OS lifecycle data leakage."
        ],
        "is_foundational": true
    },
    {
        "name": "API Rate Limiting Bypass via Header Spoofing",
        "type": "API",
        "cwe": "CWE-770",
        "owasp": "API4:2023-Unrestricted Resource Consumption",
        "description": "The API implements rate limiting based on the client's IP address. However, the logic trusts the `X-Forwarded-For`, `X-Real-IP`, or `Client-IP` headers provided by the client to determine the source address, rather than the actual transport-layer IP.",
        "impact": "Attackers can trivially bypass rate limits and anti-brute-force mechanisms by injecting a continuously changing, spoofed IP address into the HTTP header for each request.",
        "mitigation": [
            "Configure the API Gateway or Load Balancer to overwrite or strictly sanitize incoming `X-Forwarded-For` headers from the public internet.",
            "Base rate-limiting logic on the transport-layer (TCP) IP address, or on cryptographically secure, authenticated session identifiers (like user ID or API key) rather than IP addresses alone.",
            "Implement progressive delays (exponential backoff) for consecutive failed requests.",
            "Utilize CAPTCHAs to throttle high-velocity automated requests.",
            "Deploy behavioral analytics to detect distributed brute-force patterns.",
            "Ensure the proxy configuration securely passes the true client IP."
        ],
        "is_foundational": true
    },
    {
        "name": "Boolean-Based Blind SQL Injection",
        "type": "Web",
        "cwe": "CWE-89",
        "owasp": "A03:2021-Injection",
        "description": "The application is vulnerable but does not return error messages. Attackers infer data by observing differences in response content for true/false queries.",
        "impact": "Total database compromise and exfiltration of sensitive user data.",
        "mitigation": [
            "Mandate parameterized queries for every database call.",
            "Utilize a secure, well-vetted ORM framework.",
            "Implement input validation at the application layer.",
            "Restrict database permissions to minimize blast radius.",
            "Enable query performance monitoring to detect enumeration.",
            "Regularly audit code for raw SQL query construction."
        ],
        "is_foundational": true
    },
    {
        "name": "REST HTTP Method Tampering (Verb Tunneling)",
        "type": "API",
        "cwe": "CWE-650",
        "owasp": "A01:2021-Broken Access Control",
        "description": "The API restricts access based on the HTTP method (e.g., blocking POST requests for standard users). An attacker uses verb tunneling headers like `X-HTTP-Method-Override: POST` or simply changes the request method (e.g., from GET to HEAD) to bypass the access control filters while the backend still executes the intended logic.",
        "impact": "Bypass of endpoint authorization controls, leading to unauthorized data modification, creation, or deletion.",
        "mitigation": [
            "Configure the web server and API framework to strictly reject unrecognized or unsupported HTTP methods.",
            "Explicitly disable verb tunneling headers (like `X-HTTP-Method-Override`) unless absolutely required by legacy infrastructure.",
            "Enforce authorization logic at the application layer based on the requested action and data, rather than relying solely on the HTTP verb at the routing layer.",
            "Ensure HEAD requests do not inadvertently trigger state-changing backend logic.",
            "Implement strict allowlists for allowable methods per endpoint.",
            "Audit API routing configurations thoroughly."
        ],
        "is_foundational": true
    },
    {
        "name": "WebView Universal Cross-Site Scripting (UXSS)",
        "type": "Mobile",
        "cwe": "CWE-79",
        "owasp": "M6:2023-Insufficient Input/Output Validation",
        "description": "The application utilizes an outdated or misconfigured WebView component that is vulnerable to UXSS. This allows an attacker, by loading a malicious page within the WebView, to bypass the Same-Origin Policy entirely and execute scripts in the context of any other loaded domain.",
        "impact": "Complete compromise of all sessions and data handled within the WebView, leading to massive credential theft and state manipulation.",
        "mitigation": [
            "Ensure the application targets the latest Android/iOS SDKs to utilize securely patched, up-to-date system WebViews.",
            "Disable JavaScript execution in the WebView (`setJavaScriptEnabled(false)`) if it is not strictly required.",
            "Implement strict URL loading policies (using `shouldOverrideUrlLoading`) to prevent the WebView from navigating to untrusted domains.",
            "Do not load untrusted content directly into a WebView containing authenticated sessions.",
            "Utilize modern alternatives like Custom Tabs (Android) or SFSafariViewController (iOS) for browsing external content.",
            "Regularly audit the implementation of all WebView clients."
        ],
        "is_foundational": true
    },
    {
        "name": "Server-Sent Events (SSE) Cross-Origin Leakage",
        "type": "API",
        "cwe": "CWE-200",
        "owasp": "A01:2021-Broken Access Control",
        "description": "The API utilizes Server-Sent Events (SSE) to push real-time data to the client. The SSE endpoint does not enforce proper origin checks or require unpredictable session tokens, relying entirely on ambient cookies.",
        "impact": "A malicious website can initiate a cross-origin SSE connection to the vulnerable endpoint and read the continuous stream of sensitive real-time data belonging to the victim.",
        "mitigation": [
            "Require a cryptographically secure, unpredictable token (e.g., an anti-CSRF token or JWT) to be passed in the URL or custom headers when establishing the SSE connection.",
            "Strictly validate the `Origin` header during the initial HTTP handshake for the SSE stream.",
            "Do not rely exclusively on ambient cookies for authorizing cross-origin SSE streams.",
            "Implement strict CORS policies for all real-time communication endpoints.",
            "Regularly audit the authentication architecture of asynchronous APIs.",
            "Ensure sensitive data streams are encrypted at the transport layer."
        ],
        "is_foundational": true
    },
    {
        "name": "Insecure Exported Broadcast Receiver",
        "type": "Mobile",
        "cwe": "CWE-926",
        "owasp": "M1:2023-Improper Platform Usage",
        "description": "An exported Broadcast Receiver listens for specific Intents but lacks permission constraints. A malicious application can spoof internal application broadcasts, sending crafted Intents that manipulate the vulnerable app's internal logic or state.",
        "impact": "Unauthorized manipulation of app behavior, data injection, or triggering of sensitive background processes by a malicious third-party app.",
        "mitigation": [
            "Set `android:exported=\"false\"` for Broadcast Receivers intended only for internal application communication.",
            "Utilize `LocalBroadcastManager` (or newer alternatives like LiveData/StateFlow) for exclusively intra-app broadcasts.",
            "If the receiver must be exported, mandate strict signature-level permissions.",
            "Rigorously validate and sanitize all data received within the Intent payload.",
            "Avoid performing high-risk actions (like data deletion or state changes) based solely on unauthenticated broadcasts.",
            "Audit the AndroidManifest.xml for permissive receiver configurations."
        ],
        "is_foundational": true
    },
    {
        "name": "Insecure Deserialization (Python Pickle/PyYAML)",
        "type": "Web",
        "cwe": "CWE-502",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "description": "The Python application deserializes untrusted data using insecure libraries like `pickle` or `yaml.load`. These libraries permit the instantiation of arbitrary Python objects and execution of system commands during the deserialization phase.",
        "impact": "Critical Remote Code Execution (RCE) vulnerability allowing immediate server compromise.",
        "mitigation": [
            "Never deserialize untrusted data using `pickle`.",
            "Replace `yaml.load()` with the secure `yaml.safe_load()` which restricts arbitrary object instantiation.",
            "Migrate to fundamentally safer data interchange formats like JSON.",
            "Cryptographically sign serialized data to verify its origin and integrity before processing.",
            "Isolate deserialization logic in a restricted environment.",
            "Use automated SAST tools to block insecure serialization APIs."
        ],
        "is_foundational": true
    },
    {
        "name": "Unrestricted File Upload (RCE Path)",
        "type": "Web",
        "cwe": "CWE-434",
        "owasp": "A04:2021-Insecure Design",
        "description": "The application allows users to upload files without enforcing strict file type, extension, or content validation. Attackers upload malicious scripts (e.g., a .php or .jsp web shell) to an executable directory.",
        "impact": "Immediate Remote Code Execution (RCE) and full compromise of the application hosting environment.",
        "mitigation": [
            "Validate file types using strict allowlists based on actual file content (magic bytes), not just extensions.",
            "Rename uploaded files to randomized, unpredictable hashes upon receipt.",
            "Store uploaded files in an isolated directory or external cloud storage (e.g., S3) outside the web root.",
            "Configure the web server to disable code execution within the upload directory.",
            "Strip EXIF data and metadata from uploaded images.",
            "Implement antivirus scanning on all uploaded files."
        ],
        "is_foundational": true
    },
    {
        "name": "Mobile UI Redressing (Tapjacking)",
        "type": "Mobile",
        "cwe": "CWE-1021",
        "owasp": "M1:2023-Improper Platform Usage",
        "description": "The application does not adequately protect sensitive views (like permission grants or transaction confirmations) from being obscured. A malicious app uses the `SYSTEM_ALERT_WINDOW` permission to draw a transparent overlay over the vulnerable app.",
        "impact": "Users are tricked into clicking sensitive buttons (e.g., 'Confirm Transfer', 'Grant Permission') while believing they are interacting with an innocuous overlay.",
        "mitigation": [
            "Set the `filterTouchesWhenObscured` attribute to `true` on critical UI components (buttons, toggles) to discard touches when a window is drawn over them.",
            "Programmatically verify the `MotionEvent.FLAG_WINDOW_IS_OBSCURED` flag in touch listeners.",
            "Minimize the duration and necessity of highly sensitive dialogs.",
            "Request the OS to prevent overlays entirely during critical flows if the platform SDK allows.",
            "Regularly test the application against overlay attacks using automated testing frameworks.",
            "Educate users on the risks of granting the 'Draw over other apps' permission."
        ],
        "is_foundational": true
    },
    {
        "name": "Blind OS Command Injection",
        "type": "Web",
        "cwe": "CWE-78",
        "owasp": "A03:2021-Injection",
        "description": "The application executes system commands using user input but does not return the command's output to the HTTP response. Attackers infer execution using time delays (e.g., `ping -c 10 127.0.0.1`) or out-of-band network interactions.",
        "impact": "Unauthenticated Remote Code Execution (RCE) granting full control over the underlying host.",
        "mitigation": [
            "Avoid invoking operating system commands entirely; use built-in language libraries.",
            "If execution is unavoidable, use APIs that do not invoke a shell (e.g., `subprocess.run` with `shell=False` in Python).",
            "Validate input strictly against a narrow allowlist of alphanumeric characters.",
            "Restrict outbound network access from the application server (egress filtering).",
            "Run the application process within a hardened, least-privilege environment.",
            "Monitor for unexpected child process spawning."
        ],
        "is_foundational": true
    },
    {
        "name": "Mutation XSS (mXSS)",
        "type": "Web",
        "cwe": "CWE-79",
        "owasp": "A03:2021-Injection",
        "description": "An advanced XSS variant where an attacker provides seemingly benign HTML that passes sanitization, but mutates into a malicious payload when parsed and normalized by the browser's HTML rendering engine.",
        "impact": "Bypasses standard server-side WAFs and sanitization libraries (like DOMPurify if misconfigured), leading to client-side code execution.",
        "mitigation": [
            "Keep server-side and client-side HTML sanitizers updated to their absolute latest versions.",
            "Avoid passing user input through multiple rounds of parsing/rendering.",
            "Use strict CSP to prevent inline script execution regardless of DOM mutations.",
            "Render untrusted content inside a sandboxed iframe if possible.",
            "Limit the allowed HTML tags to a very bare minimum.",
            "Test inputs against known mXSS vectors (e.g., math/svg namespace switching)."
        ],
        "is_foundational": true
    },
    {
        "name": "REST Content-Type Sniffing Bypass",
        "type": "API",
        "cwe": "CWE-434",
        "owasp": "A04:2021-Insecure Design",
        "description": "The API endpoint accepts file uploads but relies entirely on the client-provided `Content-Type` header (e.g., `image/jpeg`) to validate the file's safety, rather than inspecting the actual binary content.",
        "impact": "Attackers can upload malicious executable scripts (e.g., a PHP shell) by simply spoofing the `Content-Type` header to mimic an image, leading to Remote Code Execution (RCE).",
        "mitigation": [
            "Never trust the client-provided `Content-Type` header for security validation.",
            "Inspect the actual file contents (magic bytes/file signatures) to verify the file type securely.",
            "Process and re-encode all uploaded media files using a secure library to strip extraneous data.",
            "Store all uploaded files outside of the web root or in isolated cloud storage (S3).",
            "Ensure the server does not execute files within the upload directory.",
            "Enforce the `X-Content-Type-Options: nosniff` header on the server."
        ],
        "is_foundational": true
    },
    {
        "name": "File Upload Bypass via Polyglot / Magic Bytes",
        "type": "Web",
        "cwe": "CWE-434",
        "owasp": "A04:2021-Insecure Design",
        "description": "The application attempts to validate file uploads by checking the file's 'magic bytes' (e.g., ensuring it starts with GIF89a). An attacker crafts a 'polyglot' file that is simultaneously a valid image and a valid executable script.",
        "impact": "Bypasses basic file upload protections, leading to Remote Code Execution (RCE) when the web server executes the polyglot file.",
        "mitigation": [
            "Do not rely solely on magic bytes or Content-Type headers for validation.",
            "Process and re-encode all uploaded images using a secure graphics library (e.g., stripping the file of any embedded executable content).",
            "Never store uploaded files in an executable directory.",
            "Serve user-uploaded content from an isolated, sandboxed domain.",
            "Enforce file size and dimension limits before processing.",
            "Utilize robust WAF and antivirus scanning."
        ],
        "is_foundational": true
    },
    {
        "name": "Insecure Exported Android Activity (Access Control Bypass)",
        "type": "Mobile",
        "cwe": "CWE-926",
        "owasp": "M1:2023-Improper Platform Usage",
        "description": "An Android application explicitly exports a sensitive Activity (`android:exported=\"true\"`) in the AndroidManifest.xml without enforcing custom permission checks. This allows any other app on the device to launch the Activity directly, bypassing intended application flow (like login screens).",
        "impact": "Attackers can bypass authentication interfaces, access privileged application states, or force the application to perform unauthorized actions on behalf of the user.",
        "mitigation": [
            "Set `android:exported=\"false\"` for all Activities that do not strictly need to be invoked by other applications.",
            "If an Activity must be exported, enforce strict custom Android permissions (`android:permission`) to ensure only authorized apps can launch it.",
            "Implement programmatic checks within the Activity to verify the calling intent and application state.",
            "Do not rely on the UI flow (e.g., hiding a button) as a security control.",
            "Use automated tools like MobSF to scan the manifest for exported components.",
            "Validate all data passed to the exported Activity via Intents."
        ],
        "is_foundational": true
    },
    {
        "name": "Hardcoded Cryptographic Keys in Mobile Binary",
        "type": "Mobile",
        "cwe": "CWE-798",
        "owasp": "M7:2023-Insufficient Binary Protection",
        "description": "The application hardcodes symmetric cryptographic keys or API secrets directly within the source code. Despite attempts at obfuscation, these keys remain statically embedded within the compiled APK/IPA.",
        "impact": "Adversaries can trivially reverse-engineer the application binary (using tools like jadx or Hopper), extract the static keys, and compromise encrypted local storage or spoof authenticated API requests.",
        "mitigation": [
            "Absolutely never hardcode cryptographic keys or critical API secrets within the client-side binary.",
            "Derive encryption keys dynamically at runtime using user input (e.g., PBKDF2 derived from a password) or fetch them securely from the backend post-authentication.",
            "Store keys securely in the hardware-backed Keystore or Keychain.",
            "Utilize robust code obfuscation and binary packing (e.g., ProGuard, DexGuard) to complicate static analysis.",
            "Implement Runtime Application Self-Protection (RASP) to detect reverse-engineering environments.",
            "Assume the mobile binary is entirely untrusted and will eventually be decompiled."
        ],
        "is_foundational": true
    },
    {
        "name": "gRPC Server Reflection Information Disclosure",
        "type": "API",
        "cwe": "CWE-200",
        "owasp": "API8:2023-Security Misconfiguration",
        "description": "The gRPC API is deployed with the Server Reflection protocol enabled in a production environment. This allows unauthenticated clients to query the server to discover the entire protocol buffer (protobuf) service definition.",
        "impact": "Exposes the complete internal API surface, including all services, methods, and message structures. This significantly lowers the barrier for attackers to map the attack surface and craft targeted exploits.",
        "mitigation": [
            "Explicitly disable gRPC Server Reflection in all production and public-facing environments.",
            "Restrict reflection endpoints to internal, authenticated developer networks only.",
            "Treat protobuf definitions as sensitive architectural blueprints.",
            "Implement strict authentication and authorization interceptors across all gRPC services.",
            "Regularly audit deployment configurations to ensure debug features are disabled.",
            "Monitor network traffic for unauthorized usage of the reflection service."
        ],
        "is_foundational": true
    },
    {
        "name": "Time-Based Blind SQL Injection",
        "type": "Web",
        "cwe": "CWE-89",
        "owasp": "A03:2021-Injection",
        "description": "Attackers infer data by injecting commands that cause the database to delay its response (e.g., pg_sleep()) based on a condition.",
        "impact": "Allows full data extraction, although slower than other SQLi methods.",
        "mitigation": [
            "Adopt parameterized queries across the entire codebase.",
            "Restrict the DB user's ability to execute sleep functions.",
            "Implement strict rate limiting to hinder automated enumeration.",
            "Use an ORM to handle all database communication safely.",
            "Monitor for long-running, anomalous database queries.",
            "Ensure input validation is enforced for all parameters."
        ],
        "is_foundational": true
    },
    {
        "name": "SAML XML Signature Wrapping (XSW)",
        "type": "Web",
        "cwe": "CWE-347",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "description": "The Service Provider (SP) incorrectly validates the SAML XML signature. An attacker modifies the SAML response, placing a forged assertion elsewhere in the XML tree while keeping the original, validly signed assertion intact to trick the parser.",
        "impact": "Complete authentication bypass and account takeover, allowing attackers to log in as any user (including administrators) within the SSO ecosystem.",
        "mitigation": [
            "Use established, heavily vetted SAML libraries rather than writing custom XML parsing logic.",
            "Ensure the XML parser validates the signature against the specific Assertion element being processed, not just the presence of a valid signature.",
            "Enforce strict schema validation on the SAML Response before processing.",
            "Reject SAML responses containing multiple Assertion elements if only one is expected.",
            "Keep SAML libraries updated to patch known XSW vulnerabilities.",
            "Use SAST/DAST tools specialized in SSO protocols."
        ],
        "is_foundational": true
    },
    {
        "name": "Remote File Inclusion (RFI)",
        "type": "Web",
        "cwe": "CWE-98",
        "owasp": "A03:2021-Injection",
        "description": "The application accepts a URL as input and passes it to an inclusion function (e.g., include() in PHP) without validation, allowing the application to fetch and execute remote code from an attacker-controlled server.",
        "impact": "Immediate Remote Code Execution (RCE) with the privileges of the web application service.",
        "mitigation": [
            "Disable remote file inclusion features at the language level (e.g., set allow_url_include = Off in php.ini).",
            "Never use user-supplied input to dictate the inclusion path or URL.",
            "Validate all parameters rigorously against an allowlist.",
            "Implement stringent egress network filtering to prevent the server from fetching external payloads.",
            "Adopt secure coding practices that rely on static file includes.",
            "Use SAST tools to flag unsafe inclusion patterns."
        ],
        "is_foundational": true
    },
    {
        "name": "WebView Insecure File Scheme Access (file://)",
        "type": "Mobile",
        "cwe": "CWE-74",
        "owasp": "M6:2023-Insufficient Input/Output Validation",
        "description": "The WebView is explicitly configured to allow file scheme access (`setAllowFileAccess(true)`) and JavaScript execution. An attacker who manages to execute JavaScript within the WebView (e.g., via XSS) can read arbitrary local files from the device filesystem.",
        "impact": "Theft of the application's private SQLite databases, shared preferences, and highly sensitive local tokens.",
        "mitigation": [
            "Explicitly disable file access in the WebView using `setAllowFileAccess(false)`.",
            "Disable cross-origin file access using `setAllowFileAccessFromFileURLs(false)` and `setAllowUniversalAccessFromFileURLs(false)`.",
            "If local assets must be loaded, utilize the `WebViewAssetLoader` library (Android) to serve them securely via a standard scheme (e.g., https://appassets.androidplatform.net/).",
            "Validate and sanitize any data passed into the WebView to prevent XSS.",
            "Audit all WebView instantiations across the codebase.",
            "Implement a strict CSP within the loaded HTML content."
        ],
        "is_foundational": true
    },
    {
        "name": "OAuth 2.0 Implicit Flow Token Leakage",
        "type": "Web",
        "cwe": "CWE-200",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "description": "The application utilizes the deprecated OAuth 2.0 Implicit Flow, returning access tokens directly in the URL fragment. These tokens are highly susceptible to leakage via the browser history, Referer headers, or malicious third-party scripts.",
        "impact": "Account takeover if the access token is intercepted by an attacker via network monitoring or client-side XSS.",
        "mitigation": [
            "Deprecate the OAuth 2.0 Implicit Flow entirely across the application ecosystem.",
            "Transition to the Authorization Code Flow with PKCE (Proof Key for Code Exchange) for all Single Page Applications (SPAs) and mobile apps.",
            "Ensure access tokens are short-lived.",
            "Avoid passing tokens in URLs under any circumstances.",
            "Use strict CSP to prevent malicious scripts from reading URL fragments.",
            "Implement token binding (e.g., DPoP) where supported."
        ],
        "is_foundational": true
    },
    {
        "name": "CORS Misconfiguration (Arbitrary Subdomain Trust)",
        "type": "Web",
        "cwe": "CWE-942",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "The application validates the CORS Origin header using a flawed regex (e.g., trusting anything ending in `.company.com`). An attacker registers `attackercompany.com` or takes over an abandoned subdomain to bypass the check.",
        "impact": "Exfiltration of sensitive authenticated data to an attacker-controlled domain.",
        "mitigation": [
            "Validate the Origin header strictly against a specific, static allowlist without relying on complex or flawed regular expressions.",
            "If regex is necessary, ensure it anchors both the start and end of the string correctly (e.g., `^https://(www\\.)?company\\.com$`).",
            "Regularly audit the organization's DNS records for dangling subdomains (Subdomain Takeover).",
            "Do not trust wildcard subdomains globally for sensitive APIs.",
            "Use built-in framework CORS middlewares which handle origin checking safely.",
            "Perform dynamic testing by spoofing the Origin header during assessments."
        ],
        "is_foundational": true
    }
];