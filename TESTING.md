# Big Tech Automation Blueprint: VulnPrint

Large organizations (FAANG/Cybersecurity Firms) don't build "scripts"; they build **Testing Platforms**. Here is how this project is now structured to meet those standards.

## 1. Directory Structure (Standard Naming)
*   `base/`: Infrastructure & Setup. **BaseTest.java** manages the "Global Context".
*   `pages/`: UI Abstraction. **LoginPage.java** acts as the "API" for a specific screen.
*   `utils/`: Backend Clients. **MailpitClient.java** programmatically interacts with third-party services.
*   `tests/`: Scenarios. **VulnPrintLifecycleE2E.java** is a "Single Source of Truth" for the entire application flow.

## 2. Naming Conventions (Professional)
*   **Tests**: Prefixed with `ST-` (Scenario Test) or `BT-` (Boundary Test) and followed by a clear business outcome (e.g., `ST-101: Admin Authentication`).
*   **Page Methods**: Atomic and verb-first (e.g., `fillRoleName`, `submitInvitation`).
*   **Dynamic Data**: Every entity uses a **Contextual Suffix** (`_timestamp`) to ensure "Clean Room" execution on shared databases.

## 3. The "Unified State Machine"
Unlike amateur testing which re-logs for every file, Big Tech uses **State Preservation**:
*   The `VulnPrintLifecycleE2E` class maintains a private state (e.g., `dynamicRoleName`).
*   Step 2 creates a role and saves its name.
*   Step 3 retrieves that name and assigns a user to it.
*   This replicates a **Real User's Continuous Session**, finding bugs that fragmented tests often miss.

## 4. Stability & Reliability (The "Golden Guard")
*   **No Text Reliance**: We use **Strict IDs** (e.g., `#create-role-btn`) because text labels change for translations or marketing, but IDs stay constant for developers.
*   **Asynchronous Polling**: We use **Recursive Polling** (e.g., in Mailpit) to handle network latency without using brittle "Sleep" commands.
