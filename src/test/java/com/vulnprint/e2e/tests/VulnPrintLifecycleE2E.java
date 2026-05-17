package com.vulnprint.e2e.tests;

import com.vulnprint.e2e.base.BaseTest;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * VulnPrintLifecycleE2E
 * A unified, stateful E2E suite following Big Tech "Scenario-Based" testing.
 * This class maintains a single browser session across all steps.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class VulnPrintLifecycleE2E extends BaseTest {

    // Persistent state across steps (Big Tech Pattern: Shared Context)
    private String dynamicRoleName;
    private String dynamicUserEmail;

    @Test
    @Order(1)
    @DisplayName("ST-101: Admin Authentication with MFA")
    void step1_AdminLogin() {
        surgicalAdminLogin();
        assertTrue(page.url().contains("/dashboard"), "Admin should reach dashboard after MFA");
    }

    @Test
    @Order(2)
    @DisplayName("ST-102: System Configuration (Role Provisioning)")
    void step2_CreateRole() {
        dynamicRoleName = "Auditor_Level_" + System.currentTimeMillis();
        organizationPage.navigate();
        organizationPage.clickCreateNewRole();
        
        // Provision role with necessary permissions to see and add projects/vulns
        organizationPage.fillRoleDetails(dynamicRoleName, new String[]{
            "VIEW_DASHBOARD", "VIEW_ALL_PROJECTS", "ADD_PROJECT", "DELETE_ALL_PROJECTS",
            "VIEW_ALL_VULNS", "ADD_VULNERABILITY"
        });
        organizationPage.saveRole();
        
        assertTrue(organizationPage.isRoleVisible(dynamicRoleName), "Newly created role must be visible in the registry");
    }

    @Test
    @Order(3)
    @DisplayName("ST-103: Identity Management (User Onboarding)")
    void step3_InviteUser() {
        dynamicUserEmail = "engineer_" + System.currentTimeMillis() + "@vulnprint.local";
        userMgmtPage.navigate();
        userMgmtPage.clickAddUser();
        userMgmtPage.fillInviteDetails(dynamicUserEmail, "Automated", "Tester", dynamicRoleName);
        userMgmtPage.submitInvitation();
        
        // Wait for directory list to catch up
        assertTrue(userMgmtPage.isUserVisible(dynamicUserEmail), "User must be visible in the directory after invitation");
    }

    @Test
    @Order(4)
    @DisplayName("ST-104: Secure Onboarding (Account Activation)")
    void step4_ActivateUser() {
        // 1. Admin triggers reset link (activation)
        userMgmtPage.triggerReset(dynamicUserEmail);
        
        // 2. Fetch from Mailpit
        String link = mailpit.getLatestActivationLink(dynamicUserEmail);
        assertNotNull(link, "Activation link should be found in Mailpit");
        
        // 3. Admin Logs out
        dashboardPage.logout();
        
        // 4. Activate
        page.navigate(link);
        activationPage.setPassword("StrongPassword08!");
        assertTrue(activationPage.isActivationSuccess(), "Activation should be confirmed by UI");
    }

    @Test
    @Order(5)
    @DisplayName("ST-105: Operational Lifecycle (Pentest & Findings)")
    void step5_UserOperations() {
        // 1. Login as New User
        loginPage.navigate();
        loginPage.fillCredentials(dynamicUserEmail, "StrongPassword08!");
        completeLogin(dynamicUserEmail);
        
        // 2. Create Pentest
        String pentestName = "E2E Project " + System.currentTimeMillis();
        pentestPage.navigate();
        pentestPage.clickAddPentest();
        // Fill all required fields including application name and assign the current user as tester
        pentestPage.createPentest("Lifecycle Corp", pentestName, "Web Application", "Lifecycle App", "https://app.lifecycle.com", "Automated Tester");
        
        // This method now handles waiting for the AJAX-loaded dashboard list
        assertTrue(pentestPage.isPentestVisible(pentestName), "New pentest should be visible in the dashboard list");
        
        // 3. Cleanup: Delete for idempotency
        pentestPage.deletePentest(pentestName);
    }
}
