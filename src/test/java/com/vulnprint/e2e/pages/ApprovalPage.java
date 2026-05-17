package com.vulnprint.e2e.pages;

import com.microsoft.playwright.Page;

public class ApprovalPage {
    private final Page page;

    public ApprovalPage(Page page) {
        this.page = page;
    }

    public void navigate() {
        page.navigate("http://localhost:8080/vulnerability-approver");
    }

    public void approveFinding(String title) {
        page.locator("tr:has-text('" + title + "') >> button:has-text('Approve')").first().click();
        page.waitForLoadState(com.microsoft.playwright.options.LoadState.NETWORKIDLE);
    }
}
