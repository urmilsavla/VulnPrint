# VulnPrint Ultra-Deep Authentication & Authorization Survey

This document contains a line-by-line security audit of all REST and View endpoints in the VulnPrint application, along with the complete Role-Based Access Control (RBAC) registry.

---

## 🏛️ Security Architecture Summary
- **Authentication:** Hybrid model using Stateless JWT (Access) and Stateful Refresh Tokens/Session IDs (Stored in `UserSession`).
- **Authorization:** Spring Security `@PreAuthorize` annotations coupled with a centralized `AppSecurityGuard` service for complex ownership logic.
- **Data Protection:** Global PII encryption for sensitive fields (e.g., Address) and full XSS sanitization sweep via `guard.sanitize()`.

---

## 🛡️ Immutable Root Authority (Superadmin)
The system is built upon a single, hardcoded root-of-trust: `superadmin@vulnprint.com`.
- **Global Access:** This account is permanently bound to the `Administrator` role, which holds every Permission Key in the system.
- **Immutable:** To prevent privilege escalation or accidental lockouts, the Superadmin profile is strictly immutable via the API or UI. 
- **Restrictions:** It cannot be deleted, suspended, modified, or have its password reset through the application interfaces. Any modifications to this root authority must be executed directly at the database level by a DBA.

---

## 🔑 Master Permission Registry

### 1. Global Observability
| Key | Description |
| :--- | :--- |
| `VIEW_DASHBOARD` | Access to executive metrics and the main landing interface. |
| `VIEW_ALERTS` | Ability to see system-wide security notifications and logs. |
| `MANAGE_ALERTS` | Ability to mark alerts as read or clear the notification queue. |

### 2. Project Management (Pentests)
| Key | Description |
| :--- | :--- |
| `VIEW_ASSIGNED_PROJECTS` | Access restricted to projects where the user is an assigned tester. |
| `VIEW_ALL_PROJECTS` | Administrative access to view every project in the registry. |
| `ADD_PROJECT` | Permission to register a new pentest engagement. |
| `EDIT_ASSIGNED_PROJECTS` | Ability to update details of projects assigned to the user. |
| `EDIT_ALL_PROJECTS` | Full administrative editing rights for all project records. |
| `DELETE_ASSIGNED_PROJECTS` | Permission to remove own project records (audited). |
| `DELETE_ALL_PROJECTS` | Master deletion rights for any project in the system. |
| `CHANGE_PENTEST_STATUS` | Ability to toggle project lifecycle (Active, Pending, Completed). |

### 3. Finding Documentation (Vulnerabilities)
| Key | Description |
| :--- | :--- |
| `VIEW_ASSIGNED_VULNS` | Read access for findings in assigned projects. |
| `VIEW_ALL_VULNS` | System-wide visibility for all vulnerability data. |
| `ADD_VULNERABILITY` | Ability to submit new findings to a project. |
| `EDIT_ASSIGNED_VULNS` | Editing rights for findings in owned projects. |
| `EDIT_ALL_VULNS` | Administrative editing rights for any finding. |
| `DELETE_ASSIGNED_VULNS` | Deletion rights for findings in owned projects. |
| `DELETE_ALL_VULNS` | Master deletion rights for all findings. |
| `APPROVE_ASSIGNED_VULNS` | QA/Approver rights for assigned projects. |
| `APPROVE_ALL_VULNS` | Global QA Authority (Approver Role). |
| `CHANGE_VULN_STATUS` | Technical status management (e.g., Open, Fixed, Retest). |
| `CHANGE_VULN_REPORTING_STATUS` | Reporting lifecycle management (e.g., Approved, Rejected). |

### 4. Reporting & Identity
| Key | Description |
| :--- | :--- |
| `GENERATE_REPORT` | Access to the RepGen engine to compile official PDF/Doc reports. |
| `MANAGE_REPORT_DESIGN` | Access to Organizational branding and report modularity settings. |

### 5. Governance & IAM (Identity & Access Management)
| Key | Description |
| :--- | :--- |
| `VIEW_USERS` | Access to the User Directory. |
| `MANAGE_USERS` | Full User lifecycle management (Create, Edit, Toggle). |
| `MANAGE_ACCESS` | Access Control management (Role definitions, Permission mapping). |
| `RESET_PASSWORD` | Security override for password recovery and forced resets. |
| `ENABLE_2FA` | Enforce or manage Multi-Factor Authentication settings. |

### 6. System Operations
| Key | Description |
| :--- | :--- |
| `MANAGE_MICROSERVICES` | Access to VulnDB and RepGen connector configurations. |
| `EDIT_MY_PROFILE` | Ability to update personal details and avatar. |

---

## 🗺️ Master Endpoint-to-Permission Mapping (API & Views)

This table provides a 100% comprehensive audit of every endpoint in the system and its required authorization.

### 🔓 Open & Pre-Authentication Endpoints (No Token Required)
| Area | Endpoint | Method | Note |
| :--- | :--- | :--- | :--- |
| **Auth** | `/api/auth/apply` | `POST` | Self-onboarding request. Sanitizes all PII. Checks if email is already in use. |
| **Auth** | `/api/auth/login` | `POST` | Standard login entry. Rate limited by IP. Mitigates timing attacks with dummy hash. Handles MFA logic. |
| **Auth** | `/api/auth/refresh` | `POST` | Session rotation (uses RT cookie). Validates IP/UA against stored session. |
| **Auth** | `/api/auth/verify-mfa` | `POST` | OTP verification. Validates `preAuthToken` (2-min expiry) before establishing full session. |
| **Auth** | `/api/auth/reset-password` | `POST` | Execute password reset via token. Cryptographically validates hashed token. Triggers Global Session Purge. |
| **User** | `/api/users/activate` | `POST` | Initial account setup via invite token. Revokes old sessions for security if active. |
| **View** | `/login` | `GET` | Landing page. |
| **View** | `/activate-account` | `GET` | Invitation landing page. |
| **View** | `/reset-password` | `GET` | Password reset UI. |
| **View** | `/` | `GET` | Redirect to login. |
| **Error** | `/error` | `ANY` | Global error handler. |

### 🛡️ Authenticated Endpoints (Any Valid Token Required)
| Area | Endpoint | Method | Note |
| :--- | :--- | :--- | :--- |
| **Auth** | `/api/auth/logout` | `POST` | Revokes current JWT and Sessions. |
| **Config** | `/api/config/status` | `GET` | Checks if microservices are enabled. |

### 🔑 Permission-Gated Endpoints (Keys Required)
| Primary Key | Endpoint | Method | Controller Action / In-Method Security |
| :--- | :--- | :--- | :--- |
| `VIEW_DASHBOARD` | `/api/dashboard/metrics` | `GET` | Global metrics lookup. Scoped to User's projects in Service layer. |
| `VIEW_DASHBOARD` | `/api/dashboard/recent` | `GET` | Recent activity feed. Scoped activity feed. |
| `VIEW_DASHBOARD` | `/api/dashboard/pentests` | `GET` | Paged project retrieval. Max size enforced (100). |
| `VIEW_DASHBOARD` | `/api/pentests/search` | `GET` | Unified search engine. Results post-filtered if user lacks `VIEW_ALL_PROJECTS`. |
| `VIEW_DASHBOARD` | `/dashboard` | `GET` | Main UI Dashboard. |
| `VIEW_DASHBOARD` | `/template-guide` | `GET` | Report mapping documentation. |
| `VIEW_ALERTS` | `/api/dashboard/alerts` | `GET` | Notification feed. System-wide alerts. |
| `MANAGE_ALERTS` | `/api/dashboard/alerts/{id}/read` | `POST` | Mark alerts as read. |
| `ADD_PROJECT` | `/api/pentests` | `POST` | Create new project. New project creation forces self-assignment if user lacks `MANAGE_ACCESS`. |
| `ADD_PROJECT` | `/pentest/add` | `GET` | Create project UI. |
| `VIEW_ALL_PROJECTS`* | `/api/pentests/{id}` | `GET` | Project details. Ownership check via assignment list (`@guard.canViewProject`). |
| `VIEW_ALL_PROJECTS`* | `/pentest/details/{id}` | `GET` | Project detail UI (`@guard.canViewProject`). |
| `VIEW_ALL_PROJECTS`* | `/web-pentest` | `GET` | Filtered project list. |
| `VIEW_ALL_PROJECTS`* | `/mobile-pentest` | `GET` | Filtered project list. |
| `VIEW_ALL_PROJECTS`* | `/api-pentest` | `GET` | Filtered project list. |
| `VIEW_ALL_PROJECTS`* | `/network-pentest` | `GET` | Filtered project list. |
| `VIEW_ALL_PROJECTS`* | `/source-code-pentest` | `GET` | Filtered project list. |
| `EDIT_ALL_PROJECTS`* | `/api/pentests` | `POST` | Update project details (`@guard.canEditProject`). |
| `EDIT_ALL_PROJECTS`* | `/pentest/edit/{id}` | `GET` | Edit project UI (`@guard.canEditProject`). |
| `DELETE_ALL_PROJECTS`* | `/api/pentests/{id}` | `DELETE` | Remove project record (`@guard.canDeleteProject`). Audit trail logging. |
| `CHANGE_PENTEST_STATUS`* | `/api/pentests/{id}/status` | `PATCH` | Update project lifecycle state. Triggers System Alert on status change. |
| `VIEW_ALL_VULNS`* | `/api/vulnerabilities/{id}` | `GET` | Finding detail lookup (`@guard.canViewVuln`). |
| `VIEW_ALL_VULNS`* | `/api/vulnerabilities/poc-image` | `GET` | POC image serving. **Path Traversal Shield** via `guard.isSafePath()`. |
| `ADD_VULNERABILITY`* | `/api/vulnerabilities` | `POST` | Submit new finding. Generates unique UUID folder for POCs. Sanitizes all fields. |
| `ADD_VULNERABILITY`* | `/pentest/{id}/vulnerability/add` | `GET` | Add finding UI. |
| `EDIT_ALL_VULNS`* | `/api/vulnerabilities/{id}` | `PUT/PATCH` | Edit finding details. **Hardened Lock**: If finding is "Approved", it is locked from modification. |
| `EDIT_ALL_VULNS`* | `/pentest/{pid}/vulnerability/edit/{vid}` | `GET` | Edit finding UI. |
| `DELETE_ALL_VULNS`* | `/api/vulnerabilities/{id}` | `DELETE` | Remove finding record. Blocked if finding is "Approved". |
| `APPROVE_ALL_VULNS`* | `/api/dashboard/vulnerabilities/pending` | `GET` | QA Queue feed. |
| `APPROVE_ALL_VULNS`* | `/api/vulnerabilities/{id}/approve` | `POST` | Approve/Reject finding. Triggers System Alert. |
| `APPROVE_ALL_VULNS`* | `/vulnerability-approver` | `GET` | QA Queue UI. |
| `GENERATE_REPORT` | `/api/config/repgen-url` | `GET` | RepGen endpoint lookup. |
| `GENERATE_REPORT` | `/api/repGenApi/{id}` | `GET` | Compile report data. **IDOR/Traversal Patched**: Validates `encodeFileToBase64`. |
| `GENERATE_REPORT` | `/generate-report` | `GET` | Generate report UI. |
| `MANAGE_REPORT_DESIGN` | `/api/organization` | `GET/PUT` | Brand/Disclaimer management. |
| `MANAGE_REPORT_DESIGN` | `/api/pentests/{id}/report-details` | `PUT` | Project-specific design. Sanitizes all strings. |
| `MANAGE_REPORT_DESIGN` | `/pentest/report-designer/{id}` | `GET` | Design tile UI. |
| `MANAGE_REPORT_DESIGN` | `/organization-settings` | `GET` | Organizational setup UI. |
| `VIEW_USERS` | `/api/users` | `GET` | User Directory lookup. PII Decryption performed for display. |
| `VIEW_USERS` | `/api/users/check-email` | `GET` | Duplicate check utility. |
| `VIEW_USERS` | `/api/users/profile/{email}` | `GET` | Target profile view. Ownership or master view. |
| `MANAGE_USERS` | `/api/users/requests` | `GET/POST` | Access request queue management. |
| `MANAGE_USERS` | `/api/users/invite` | `POST` | Generate activation links. MD5 hashed in DB migrated to SHA-256. |
| `MANAGE_USERS` | `/api/users/profile` | `POST` | Master profile/account update. Enforces NIST strength. Blocked for Superadmin modifications by others. |
| `MANAGE_USERS` | `/api/users/{id}/status` | `PATCH` | Enable/Disable accounts. Blocked for Superadmin/Administrator. |
| `MANAGE_USERS` | `/api/users/{id}` | `DELETE` | Terminate user access. Blocked for Superadmin/Administrator. |
| `MANAGE_USERS` | `/api/users/register` | `POST` | Create new personnel record. |
| `MANAGE_USERS` | `/api/users/{id}/trigger-reset` | `POST` | Trigger reset link for user. |
| `MANAGE_USERS` | `/user-management` | `GET` | IAM Management UI. |
| `MANAGE_ACCESS` | `/api/users/roles` | `GET/POST/DELETE` | Role & Designation setup. Checks for duplicates. Blocked for Administrator deletion. |
| `MANAGE_ACCESS` | `/api/users/roles/{id}/perms` | `POST` | Role-permission mapping. **Global Purge**: Kills all user sessions with this role. |
| `MANAGE_ACCESS` | `/api/users/permissions` | `GET` | Authority registry lookup. |
| `MANAGE_ACCESS` | `/api/users/lockdown-reset` | `POST` | Emergency session invalidation. |
| `MANAGE_ACCESS` | `/api/users/{id}/permissions/reset` | `POST` | Revoke manual overrides. |
| `MANAGE_ACCESS` | `/manage-access` | `GET` | Role & Matrix UI. |
| `EDIT_MY_PROFILE` | `/profile` | `GET` | My Profile UI. |
| `EDIT_MY_PROFILE` | `/api/users/me/trigger-reset` | `POST` | Trigger self reset link (transmits email). |
| `MANAGE_MICROSERVICES` | `/api/config` | `GET/PUT` | Global system configurations. Sanitizes keys/values. |
| `MANAGE_MICROSERVICES` | `/api/config/test-connection` | `GET` | Microservice probing. **SSRF Hardened** via `guard.resolveSafeUrl()`. |
| `MANAGE_MICROSERVICES` | `/api/vulndb/search` | `GET` | VulnDB intelligence search. |
| `MANAGE_MICROSERVICES` | `/api/vulndb/vulns/{slug}` | `GET` | VulnDB detail lookup. Traversal protection on slug. |
| `MANAGE_MICROSERVICES` | `/microservice-management` | `GET` | Service control UI. |

*\* Indicates that these endpoints also have an `ASSIGNED` counterpart (e.g., `VIEW_ASSIGNED_PROJECTS`) which is handled via complex security logic within the controller or service layer.*

---

## 📋 Management Procedures

### Granting Permissions
1. Navigate to **Administration > Access Control**.
2. Select a **Role** (to apply changes globally) or a **User** (to apply individual manual overrides).
3. Toggle the desired keys within the categorized matrix.
4. Click **Save Changes** to commit.

### Troubleshooting "Permission Denied"
If a user receives a 403 error despite having the correct keys:
1. Ensure the backend `AppSecurityGuard.java` constant matches the UI key.
2. Instruct the user to **Log Out and Log In** again to refresh their JWT authority cache.
3. Check the **System Alerts** for any immediate security blocks or lockouts.

---

## 🔎 Security Observations & Hardening Notes
1. **SSRF Hardening (Patched):** Previously, `AppSecurityGuard.resolveSafeUrl()` used a flawed `startsWith` check that permitted bypasses via basic authentication components (e.g., `http://localhost:8000@169.254.169.254`). This was successfully remediated to parse the URL and validate the hostname correctly against a strict internal service whitelist or external address validation.
2. **Timing Attacks:** The login process uses a `dummyHash` to ensure consistent response times regardless of whether the user exists.
3. **Session Purge:** Password resets and permission changes trigger a global session invalidation by updating `lastRoleChange`.
4. **XSS Protection:** Every user-controllable field is passed through a central sanitization logic before storage.
5. **PII Safety:** Addresses are encrypted at rest in the database using the internal Vault service.
6. **Cryptography Standardization (Patched):** Invitation tokens and activation links in `UserRestController` previously utilized MD5 hashing, which is cryptographically weak and prone to collisions. These have been migrated to the `guard.hashToken()` method using SHA-256 for uniform security.
7. **Privilege Escalation Protection (Patched):** Discovered a significant authorization bypass in `/api/users/profile` where any user with `MANAGE_USERS` or `MANAGE_ACCESS` could modify the Administrator's password, role, or permissions. Explicit checks were added to prevent non-Administrators from mutating the Administrator profile. Furthermore, a new **Immutable Superadmin** (`superadmin@vulnprint.com`) has been introduced. This root account is strictly blocked from all API modifications (edits, suspends, deletes, role updates, password resets) to prevent hostile takeovers or accidental lockouts. Any modifications to this account must be performed directly at the database tier.
8. **Cross-Project Image IDOR (Patched):** The `/api/vulnerabilities/poc-image` endpoint previously verified path traversal against the global `UPLOAD_DIR`, allowing an attacker to read images from unauthorized pentests using `../` segments. It was hardened to validate safe paths strictly against the finding's dedicated `v.getPocFolderPath()`.
9. **Report Generation IDOR (Patched):** In `ReportDataService.java`, the `encodeFileToBase64` method compiled images for reports directly. Hardened by wrapping the file read operation with an explicit `!guard.isSafePath()` check to neutralize traversal poisoning in DB records.

*Audit Completed: May 2026 // VulnPrint Security Engineering Team*
