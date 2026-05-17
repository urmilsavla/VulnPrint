package com.vulnprint.e2e.pages;

import com.microsoft.playwright.Page;

public class UserMgmtPage {
    private final Page page;

    public UserMgmtPage(Page page) { this.page = page; }

    public void navigate() { 
        page.navigate("http://localhost:8080/user-management"); 
    }

    public void clickAddUser() {
        page.click("button:has-text('Add User')");
    }

    public void fillInviteDetails(String email, String first, String last, String role) {
        page.fill("#invite-email", email);
        page.fill("#invite-first-name", first);
        page.fill("#invite-last-name", last);
        // Match role by label (uppercase is usually how it's rendered)
        page.selectOption("#invite-role", new com.microsoft.playwright.options.SelectOption().setLabel(role.toUpperCase()));
    }

    public void submitInvitation() {
        page.click("#invite-submit-btn");
        // Wait for the modal to hide
        page.waitForSelector("#invite-modal", new com.microsoft.playwright.Page.WaitForSelectorOptions().setState(com.microsoft.playwright.options.WaitForSelectorState.HIDDEN).setTimeout(10000));
    }

    public boolean isUserVisible(String email) {
        try {
            // Wait up to 5 seconds for the user to appear
            page.waitForSelector("#directory-list >> text=" + email, new com.microsoft.playwright.Page.WaitForSelectorOptions().setTimeout(5000));
            return true;
        } catch (Exception e) {
            // If not found, try one manual reload to force the fetch
            page.reload();
            page.waitForLoadState();
            return page.isVisible("#directory-list >> text=" + email);
        }
    }

    public void triggerReset(String email) {
        page.click("#directory-list >> text=" + email);
        page.waitForTimeout(500);
        page.click("#reset-pwd-btn");
        page.waitForTimeout(500);
        // Exact ID for the confirmation button
        page.click("#confirm-reset-btn");
    }
}
