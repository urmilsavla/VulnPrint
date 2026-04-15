package com.vulnprint.service;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.options.LoadState;
import org.springframework.stereotype.Service;

@Service
public class ReportService {

    public byte[] generatePdfReport(String url) {
        try (Playwright playwright = Playwright.create()) {
            BrowserType.LaunchOptions launchOptions = new BrowserType.LaunchOptions().setHeadless(true);
            Browser browser = playwright.chromium().launch(launchOptions);
            Page page = browser.newPage();
            
            // Navigate to the report view
            page.navigate(url);
            
            // Wait for network to be idle to ensure fonts/charts are loaded
            page.waitForLoadState(LoadState.NETWORKIDLE);
            
            // Generate PDF
            Page.PdfOptions pdfOptions = new Page.PdfOptions()
                    .setFormat("A4")
                    .setPrintBackground(true)
                    .setMargin(new com.microsoft.playwright.options.Margin()
                            .setTop("0px")
                            .setBottom("0px")
                            .setLeft("0px")
                            .setRight("0px"));
                            
            byte[] pdfBytes = page.pdf(pdfOptions);
            browser.close();
            return pdfBytes;
        }
    }
}
