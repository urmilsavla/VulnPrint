package com.vulnprint.e2e.pages;

import com.microsoft.playwright.Page;

public class ActivationPage {
    private final Page page;

    public ActivationPage(Page page) { this.page = page; }

    public void setPassword(String password) {
        page.waitForLoadState();
        if (page.isVisible("#password")) {
            page.fill("#password", password);
        } else if (page.isVisible("#newPassword")) {
            page.fill("#newPassword", password);
        }
        page.fill("#confirmPassword", password);
        page.click("#submit-btn");
        page.waitForTimeout(1000);
    }

    public boolean isActivationSuccess() {
        return page.url().contains("/login") || 
               page.isVisible("text=Security credentials updated") || 
               page.isVisible("text=successfully");
    }
}
