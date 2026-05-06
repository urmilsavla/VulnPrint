# VulnPrint Project Instructions

This document provides foundational mandates, architectural context, and technical standards for the VulnPrint codebase. Adhere to these instructions for all modifications and new feature implementations.

## 🎯 Strategic Intent
VulnPrint is a professional Pentest Reporting and Management platform. All changes must prioritize security, structural integrity, and a sleek "Terminal Elite" UI/UX aesthetic.

---

## 🛡️ Security & Access Control Mandates

### 1. Role-Based Access Control (RBAC)
The system defines two primary roles (refer to `DataInitializer.java`):
- **Administrator:** Full system access, including User Management, Access Control, and Global Approvals.
- **Penetration Tester:** Scoped access to assigned projects, finding creation, and profile management.
- **Permission Keys:** Always use constants from `AppSecurityGuard` (e.g., `VIEW_ALL_PROJECTS`, `APPROVE_ALL_VULNS`).

### 2. Endpoint Protection & Method Security
- **Mandatory:** Every new or modified REST endpoint MUST have a `@PreAuthorize` annotation.
- **Service-Level Guards:** Use `@guard` methods for complex logic (e.g., `@guard.canEditProject(#id)`).
- **Validation:** Always verify the "keys logic" (JWT validation and permission checking) within `com.vulnprint.security.AppSecurityGuard`.

### 3. Centralized Security Core
- **AppSecurityGuard:** The monolithic security engine for:
  - JWT Authentication (Cookie `JWT` or `Authorization: Bearer`).
  - XSS Sanitization (`sanitize` method) - **Apply to all user-provided strings.**
  - SSRF Protection (`isSafeUrl`).
  - Path Traversal Shielding (`isSafePath`).
  - Image Processing (`processAndSaveImage`) for POC uploads.

---

## 🏗️ Data Handling & Logic Patterns

### 1. Finding & Identity Management
- **Status Lifecycle:** `Submitted` -> `Active` (if approved) | `Rejected`.
- **Identity Credentials:** 'Location' and 'Professional Qualifications' are mandatory for official reporting accuracy.
- **Reporting Status:** Managed via `CHANGE_VULN_REPORTING_STATUS` permission.
- **Technical Status:** (e.g., Open, Fixed) Managed via `CHANGE_VULN_STATUS` permission.
- **Approvals:** Use `/api/vulnerabilities/{id}/approve` with `APPROVE` or `REJECT` actions.
- **POC Storage:** Images are stored in `uploads/{pentestId}/{uuid}/`. Use `guard.processAndSaveImage` for safe handling.

### 2. Global Error & Validation
- **Exceptions:** Managed by `GlobalExceptionHandler`.
- **Validation Errors:** Return a professional message: "Please fill in all required fields marked with an asterisk (*)."
- **Correlation IDs:** Generated for all 500 errors to facilitate support.

---

## 🎨 UI/UX & Aesthetic Standards

### 1. Global UI Utilities
- All pages must include `fragments/header.html` and `fragments/sidebar.html`.
- **Feedback:** Use `window.showNotification(message, type)` for all event feedback. Types: `info`, `success`, `error`.
- **Confirmation:** Every impactful action (delete, save, logout) MUST use `window.askPermission(message)` to trigger the global confirmation modal.

### 2. Design System
- **Theme:** Dark mode by default (neon green `#4FFE49` accents).
- **Typography:** `Space Grotesk` for headlines, `Inter` for body.
- **Common Components:** Adhere to `panel-terminal`, `btn-primary`, `input-terminal`, and `heading-main` classes.

### 3. Feature Mapping
- **Dashboard:** Metrics and recent activity (`/api/dashboard`).
- **Report Designer:** Modular tile configuration (`report-designer.html`).
- **Vulnerability Approver:** Dedicated interface for status changes.

---

## 📝 Terminology & Communication

### 1. Restricted Words
Do NOT use the following terms in code, comments, or UI:
- `node`
- `purge` / `puge`
- `registry`
- `synchronize` / `syn` / `sync`

### 2. Professional Tone
- Use simple, direct, and professional language.
- Use terms like: "System Administration", "Vulnerability Approver", "Organizational Details", "Microservice Management".

---

## 🚀 Architecture Evolution & High-Fidelity Standards (Mandatory)

### 1. Service-Layer Consolidation (Anti-Leak Pattern)
- **Observation:** Business logic (risk scores, metrics calculation) is leaking into `DashboardRestController`.
- **Mandate:** ALL business-heavy calculations MUST reside in a dedicated `@Service`. Controllers should only handle request mapping and response orchestration.
- **Goal:** Keep the "Brain" in the Service layer to enable unit testing and cross-service reuse.

### 2. Stateful-Stateless Hybrid Security (The Hybrid Token Pattern)
- **Observation:** VulnPrint uses a hybrid session model:
  - **Stateless:** JWT (`JWT` cookie) for 15-minute authorization.
  - **Stateful:** Refresh Tokens (`RT`) and Session IDs (`SID`) for session rotation and centralized invalidation.
- **Mandate:** Any change to authentication MUST respect this dual-layer flow. Never bypass the `AuthCoreService` for session establishment. Use `guard.blockToken(token)` for immediate logout (stateless invalidation).

### 3. Microservice Integration & SSRF Hardening
- **Observation:** `VulnDbService` and `RepGen` use external connections.
- **Mandate:** Every external microservice connector MUST use the `guard.isSafeUrl()` check before client instantiation.
- **Data Integrity:** All external IDs/Slugs (e.g., `slug` from VulnDB) MUST be sanitized to prevent "Upstream Path Traversal."

### 4. Advanced NIST-Compliant Authentication
- **Observation:** The system supports MFA.
- **Mandate:** Respect the `preAuthToken` flow for MFA challenges. Do NOT issue a full `JWT` until the `verify-mfa` trap is cleared.

---

## 🛡️ Senior Engineer Hardening Standards (Mandatory)

### 1. Chain of Custody (Audit Logging)
- **Observation:** Status changes in pentest reports are sensitive.
- **Mandate:** Any modification to `VulnerabilityStatus`, `ReportingStatus`, or `PentestStatus` MUST trigger an entry in the `AlertRepository` with the level `System`. This ensures a clear audit trail of "Who approved what."

### 2. Environment & Key Safety
- **Observation:** `AppSecurityGuard` has a weak fallback for JWT keys.
- **Mandate:** Never modify the security constructor to include hardcoded secrets. If `VULNPRINT_JWT_SECRET` is missing, the system must log a `CRITICAL` alert to the dashboard immediately upon startup.

### 3. File System Integrity
- **Observation:** Path traversal logic is present but must be strictly applied.
- **Mandate:** All file operations (uploads/POC reads) MUST use `toRealPath()` and be checked against the `UPLOAD_DIR` constant. No exceptions.

### 4. Professional Communication Layer
- **Mandate:** Avoid "Technical Jargon" in UI notifications.
- **Instead of:** "403 Forbidden: JWT Expired"
- **Use:** "Session Expired: Please sign in again to continue."
- **Instead of:** "NullPointerException in Controller"
- **Use:** "Information Missing: Please complete all required fields."

---

## 📂 Key File Directory

| Area | Key Files / Paths |
| :--- | :--- |
| **Security** | `com.vulnprint.security.AppSecurityGuard`, `AppSecurityGuard` |
| **RBAC Setup** | `com.vulnprint.DataInitializer` |
| **Controllers** | `com.vulnprint.controller.*` |
| **Vulnerability Logic**| `com.vulnprint.controller.VulnerabilityRestController` |
| **UI Fragments** | `src/main/resources/templates/fragments/header.html`, `sidebar.html` |
| **Global Error** | `com.vulnprint.config.GlobalExceptionHandler` |

---

## 🚀 Workflow for New Tasks
1. **Initialize:** Read this `GEMINI.md` file and keep all mandates in memory.
2. **Research:** Map the task to existing controllers, services, and fragments.
3. **Implement:**
   - Add `@PreAuthorize` to endpoints.
   - Use `AppSecurityGuard.sanitize()` for all inputs.
   - Implement `askPermission` and `showNotification` for UI events.
4. **Validate:** Ensure all events return a "Pass" or "Failed" status (Success/Error notification).
cation).
