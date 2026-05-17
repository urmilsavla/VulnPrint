package com.vulnprint.e2e.pages;

import com.microsoft.playwright.Page;

public class OrganizationPage {
    private final Page page;

    public OrganizationPage(Page page) { this.page = page; }

    public void navigate() { 
        page.navigate("http://localhost:8080/manage-access"); 
        page.waitForLoadState(com.microsoft.playwright.options.LoadState.NETWORKIDLE);
    }

    public void navigateToManageAccess() {
        navigate();
    }

    public void clickCreateNewRole() {
        page.click("button:has-text('Create New Role')");
    }

    public void clickCreateRole() {
        clickCreateNewRole();
    }

    public void fillRoleName(String name) {
        page.fill("#new-role-name", name);
    }

    public void fillRoleDetails(String name, String[] permissions) {
        // 1. Enter the role name in the modal
        page.fill("#new-role-name", name);
        
        // 2. Submit the registration modal
        page.click("#create-role-btn");
        page.waitForTimeout(2000); // Wait for list refresh and init()
        
        // 3. Select the role from the left list to load the permission matrix
        // Use case-insensitive text match to be robust
        page.locator("#target-list >> text=" + name).click();
        page.waitForTimeout(1500);

        // 4. Select permissions
        if (permissions != null) {
            for (String perm : permissions) {
                String displayPerm = perm.replace("_", " ");
                // Look for the permission text and find the checkbox next to it
                // Based on manage-access.html structure: <p>...PERM NAME</p> followed by <input type="checkbox">
                com.microsoft.playwright.Locator checkbox = page.locator("div.perm-card:has(p:has-text('" + displayPerm + "')) >> input[type='checkbox']");
                checkbox.check(new com.microsoft.playwright.Locator.CheckOptions().setForce(true));
                // Wait a bit for the re-render after each toggle
                page.waitForTimeout(500);
            }
        }
    }

    public void submitRoleCreation() {
        // This is used for the simple name-only creation
        page.click("#create-role-btn");
    }

    public void saveRole() {
        // This clicks the 'Save Changes' button in the permission matrix panel
        page.click("button:has-text('Save Changes')");
        // Wait for the success notification to ensure backend processing is complete
        try {
            page.waitForSelector("text=The role permissions have been updated successfully", 
                new com.microsoft.playwright.Page.WaitForSelectorOptions().setTimeout(5000));
        } catch (Exception e) {
            // Fallback if notification is too fast or missed
            page.waitForTimeout(1000);
        }
        page.waitForTimeout(1000);
    }

    // Atomic Helper for full creation
    public void createRole(String name) {
        clickCreateNewRole();
        fillRoleName(name);
        submitRoleCreation();
    }

    public boolean isRoleVisible(String name) {
        return page.isVisible("#target-list >> text=" + name);
    }
}
