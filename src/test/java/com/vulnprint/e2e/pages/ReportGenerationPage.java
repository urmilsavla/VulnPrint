package com.vulnprint.e2e.pages;

import com.microsoft.playwright.Page;

public class ReportGenerationPage {
    private final Page page;

    public ReportGenerationPage(Page page) {
        this.page = page;
    }

    public boolean isRepGenOnline() {
        return page.isVisible(".status-online") || page.isVisible("text=ONLINE");
    }

    public void generateReport(String format) {
        page.selectOption("#report-format", format);
        page.click("#btn-generate-report");
    }

    public boolean isGenerating() {
        return page.isVisible("text=Generating...");
    }
}
