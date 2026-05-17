package com.vulnprint.e2e.pages;

import com.microsoft.playwright.Page;

public class DashboardPage {
    private final Page page;

    public DashboardPage(Page page) { this.page = page; }

    public boolean isAt() {
        return page.url().endsWith("/dashboard");
    }

    public void logout() {
        page.locator("#sidebar button[onclick*='logout']").click();
        page.waitForTimeout(500);
        if (page.isVisible("button:has-text('Confirm')")) {
            page.click("button:has-text('Confirm')");
        }
        page.waitForTimeout(1000);
    }
}
