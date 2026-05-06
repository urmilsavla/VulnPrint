# VulnPrint Security & RBAC Documentation

This document provides a comprehensive overview of the VulnPrint Role-Based Access Control (RBAC) system, including all permission keys, security workflows, and management procedures.

## 🎯 Architecture Overview
VulnPrint employs a hybrid security model:
- **Stateless Authorization:** JWT-based access tokens (15-minute lifespan).
- **Stateful Session Management:** Refresh tokens and Session IDs for centralized invalidation and rotation.
- **Granular AppSecurityGuard:** Over 30 specific authority keys mapped to endpoints and UI elements.

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

## 🛡️ Security Guardrails

### 1. SSRF Whitelist
Trusted microservices are whitelisted in `AppSecurityGuard.isSafeUrl()`:
- `http://localhost:8000/` (VulnDB)
- `http://localhost:3000/` (RepGen)

### 2. Administrator Priority
The authorization logic in `UserRestController` is hardened to ensure that `MANAGE_USERS` always provides an override pass. This prevents Administrators from being locked out of account management tasks even if they lack specific "self-edit" flags.

### 3. Audit Trail
All high-impact status changes (`PentestStatus`, `VulnerabilityStatus`, `ReportingStatus`) are automatically logged to the **System Alerts** repository with a `System` level priority for accountability.

---

## 📋 Management Procedures

### Granting AppSecurityGuard
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

## 🗺️ Master Endpoint-to-Permission Mapping

This table provides a 100% comprehensive audit of every endpoint in the system and its required authorization.

### 🔓 Open & Pre-Authentication Endpoints (No Token Required)
| Area | Endpoint | Method | Note |
| :--- | :--- | :--- | :--- |
| **Auth** | `/api/auth/apply` | `POST` | Self-onboarding request. |
| **Auth** | `/api/auth/login` | `POST` | Standard login entry. |
| **Auth** | `/api/auth/refresh` | `POST` | Session rotation (uses RT cookie). |
| **Auth** | `/api/auth/verify-mfa` | `POST` | OTP verification. |
| **User** | `/api/users/activate` | `POST` | Initial account setup via invite token. |
| **View** | `/login` | `GET` | Landing page. |
| **View** | `/activate-account` | `GET` | Invitation landing page. |
| **View** | `/` | `GET` | Redirect to login. |
| **Error** | `/error` | `ANY` | Global error handler. |

### 🛡️ Authenticated Endpoints (Any Valid Token Required)
| Area | Endpoint | Method | Note |
| :--- | :--- | :--- | :--- |
| **Auth** | `/api/auth/logout` | `POST` | Revokes current JWT. |
| **Config** | `/api/config/status` | `GET` | Checks if microservices are enabled. |

### 🔑 Permission-Gated Endpoints (Keys Required)
| Primary Key | Endpoint | Method | Controller Action |
| :--- | :--- | :--- | :--- |
| `VIEW_DASHBOARD` | `/api/dashboard/metrics` | `GET` | Global metrics lookup. |
| `VIEW_DASHBOARD` | `/api/dashboard/recent` | `GET` | Recent activity feed. |
| `VIEW_DASHBOARD` | `/api/dashboard/pentests` | `GET` | Paged project retrieval. |
| `VIEW_DASHBOARD` | `/api/pentests/search` | `GET` | Unified search engine. |
| `VIEW_DASHBOARD` | `/dashboard` | `GET` | Main UI Dashboard. |
| `VIEW_DASHBOARD` | `/template-guide` | `GET` | Report mapping documentation. |
| `VIEW_ALERTS` | `/api/dashboard/alerts` | `GET` | Notification feed. |
| `MANAGE_ALERTS` | `/api/dashboard/alerts/{id}/read` | `POST` | Mark alerts as read. |
| `ADD_PROJECT` | `/api/pentests` | `POST` | Create new project. |
| `ADD_PROJECT` | `/pentest/add` | `GET` | Create project UI. |
| `VIEW_ALL_PROJECTS`* | `/api/pentests/{id}` | `GET` | Project details (complex check). |
| `VIEW_ALL_PROJECTS`* | `/pentest/details/{id}` | `GET` | Project detail UI (complex check). |
| `VIEW_ALL_PROJECTS`* | `/web-pentest` | `GET` | Filtered project list. |
| `VIEW_ALL_PROJECTS`* | `/mobile-pentest` | `GET` | Filtered project list. |
| `VIEW_ALL_PROJECTS`* | `/api-pentest` | `GET` | Filtered project list. |
| `VIEW_ALL_PROJECTS`* | `/network-pentest` | `GET` | Filtered project list. |
| `VIEW_ALL_PROJECTS`* | `/source-code-pentest` | `GET` | Filtered project list. |
| `EDIT_ALL_PROJECTS`* | `/api/pentests` | `POST` | Update project details. |
| `EDIT_ALL_PROJECTS`* | `/pentest/edit/{id}` | `GET` | Edit project UI. |
| `DELETE_ALL_PROJECTS`* | `/api/pentests/{id}` | `DELETE` | Remove project record. |
| `CHANGE_PENTEST_STATUS`* | `/api/pentests/{id}/status` | `PATCH` | Update project lifecycle state. |
| `VIEW_ALL_VULNS`* | `/api/vulnerabilities/{id}` | `GET` | Finding detail lookup. |
| `VIEW_ALL_VULNS`* | `/api/vulnerabilities/poc-image` | `GET` | POC image serving. |
| `ADD_VULNERABILITY`* | `/api/vulnerabilities` | `POST` | Submit new finding. |
| `ADD_VULNERABILITY`* | `/pentest/{id}/vulnerability/add` | `GET` | Add finding UI. |
| `EDIT_ALL_VULNS`* | `/api/vulnerabilities/{id}` | `PUT/PATCH` | Edit finding details. |
| `EDIT_ALL_VULNS`* | `/pentest/{pid}/vulnerability/edit/{vid}` | `GET` | Edit finding UI. |
| `DELETE_ALL_VULNS`* | `/api/vulnerabilities/{id}` | `DELETE` | Remove finding record. |
| `APPROVE_ALL_VULNS`* | `/api/dashboard/vulnerabilities/pending` | `GET` | QA Queue feed. |
| `APPROVE_ALL_VULNS`* | `/api/vulnerabilities/{id}/approve` | `POST` | Approve/Reject finding. |
| `APPROVE_ALL_VULNS`* | `/vulnerability-approver` | `GET` | QA Queue UI. |
| `GENERATE_REPORT` | `/api/config/repgen-url` | `GET` | RepGen endpoint lookup. |
| `GENERATE_REPORT` | `/api/repGenApi/{id}` | `GET` | Compile report data. |
| `GENERATE_REPORT` | `/generate-report` | `GET` | Generate report UI. |
| `MANAGE_REPORT_DESIGN` | `/api/organization` | `GET/PUT` | Brand/Disclaimer management. |
| `MANAGE_REPORT_DESIGN` | `/api/pentests/{id}/report-details` | `PUT` | Project-specific design. |
| `MANAGE_REPORT_DESIGN` | `/pentest/report-designer/{id}` | `GET` | Design tile UI. |
| `MANAGE_REPORT_DESIGN` | `/organization-settings` | `GET` | Organizational setup UI. |
| `VIEW_USERS` | `/api/users` | `GET` | User Directory lookup. |
| `VIEW_USERS` | `/api/users/check-email` | `GET` | Duplicate check utility. |
| `VIEW_USERS` | `/api/users/profile/{email}` | `GET` | Target profile view. |
| `MANAGE_USERS` | `/api/users/requests` | `GET/POST` | Access request queue management. |
| `MANAGE_USERS` | `/api/users/invite` | `POST` | Generate activation links. |
| `MANAGE_USERS` | `/api/users/profile` | `POST` | Master profile/account update. |
| `MANAGE_USERS` | `/api/users/{id}/status` | `PATCH` | Enable/Disable accounts. |
| `MANAGE_USERS` | `/api/users/{id}` | `DELETE` | Terminate user access. |
| `MANAGE_USERS` | `/api/users/register` | `POST` | Create new personnel record. |
| `MANAGE_USERS` | `/user-management` | `GET` | IAM Management UI. |
| `MANAGE_ACCESS` | `/api/users/roles` | `GET/POST/DELETE` | Role & Designation setup. |
| `MANAGE_ACCESS` | `/api/users/roles/{id}/perms` | `POST` | Role-permission mapping. |
| `MANAGE_ACCESS` | `/api/users/permissions` | `GET` | Authority registry lookup. |
| `MANAGE_ACCESS` | `/api/users/lockdown-reset` | `POST` | Emergency session invalidation. |
| `MANAGE_ACCESS` | `/api/users/{id}/permissions/reset` | `POST` | Revoke manual overrides. |
| `MANAGE_ACCESS` | `/manage-access` | `GET` | Role & Matrix UI. |
| `RESET_PASSWORD` | `/api/users/change-password` | `POST` | Master password override. |
| `RESET_PASSWORD` | `/reset-password` | `GET` | Password reset UI. |
| `EDIT_MY_PROFILE` | `/profile` | `GET` | My Profile UI. |
| `MANAGE_MICROSERVICES` | `/api/config` | `GET/PUT` | Global system configurations. |
| `MANAGE_MICROSERVICES` | `/api/config/test-connection` | `GET` | Microservice probing. |
| `MANAGE_MICROSERVICES` | `/api/vulndb/search` | `GET` | VulnDB intelligence search. |
| `MANAGE_MICROSERVICES` | `/api/vulndb/vulns/{slug}` | `GET` | VulnDB detail lookup. |
| `MANAGE_MICROSERVICES` | `/microservice-management` | `GET` | Service control UI. |

*\* Indicates that these endpoints also have an `ASSIGNED` counterpart (e.g., `VIEW_ASSIGNED_PROJECTS`) which is handled via complex security logic within the controller or service layer.*

---
*Last Updated: May 2026 // VulnPrint Security Engineering Team*
