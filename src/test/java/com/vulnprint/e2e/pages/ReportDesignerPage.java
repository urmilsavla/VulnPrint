package com.vulnprint.e2e.pages;

import com.microsoft.playwright.Page;

public class ReportDesignerPage {
    private final Page page;

    public ReportDesignerPage(Page page) {
        this.page = page;
    }

    public void fillExecutiveSummary(String text) {
        page.fill("#val-executiveSummary", text);
    }

    public void saveConfiguration() {
        page.click("button:has-text('Save Configuration')");
        // Wait for redirect back to details page
        page.waitForURL("**/pentest/details/*", new com.microsoft.playwright.Page.WaitForURLOptions().setTimeout(5000));
    }
}
