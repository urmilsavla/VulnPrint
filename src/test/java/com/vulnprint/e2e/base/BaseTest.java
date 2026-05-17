package com.vulnprint.e2e.base;

import com.microsoft.playwright.*;
import com.vulnprint.e2e.pages.*;
import com.vulnprint.e2e.utils.MailpitClient;
import org.junit.jupiter.api.*;

public class BaseTest {
    protected static Playwright playwright;
    protected static Browser browser;
    protected static BrowserContext context;
    protected static Page page;
    
    // Page Objects
    protected LoginPage loginPage;
    protected DashboardPage dashboardPage;
    protected UserMgmtPage userMgmtPage;
    protected OrganizationPage organizationPage;
    protected PentestPage pentestPage;
    protected VulnerabilityPage vulnerabilityPage;
    protected ActivationPage activationPage;
    protected MailpitClient mailpit;

    @BeforeAll
    static void launchBrowser() {
        playwright = Playwright.create();
        browser = playwright.chromium().launch(new BrowserType.LaunchOptions()
            .setHeadless(false)
            .setSlowMo(100));
    }

    @AfterAll
    static void closeBrowser() {
        if (context != null) context.close();
        if (playwright != null) playwright.close();
    }

    @BeforeEach
    void setup() {
        if (page == null) {
            context = browser.newContext();
            page = context.newPage();
        }
        
        loginPage = new LoginPage(page);
        dashboardPage = new DashboardPage(page);
        userMgmtPage = new UserMgmtPage(page);
        organizationPage = new OrganizationPage(page);
        pentestPage = new PentestPage(page);
        vulnerabilityPage = new VulnerabilityPage(page);
        activationPage = new ActivationPage(page);
        mailpit = new MailpitClient(playwright);
    }

    @AfterEach
    void tearDown(TestInfo testInfo) {
        if (page != null) {
            if (!page.url().equals("about:blank")) {
                String testName = testInfo.getDisplayName().replace(" ", "_");
                try {
                    page.screenshot(new Page.ScreenshotOptions().setPath(java.nio.file.Paths.get("target/screenshots/" + testName + ".png")));
                } catch (Exception e) {}
            }
        }
    }

    protected void surgicalAdminLogin() {
        loginPage.navigate();
        loginPage.fillCredentials("superadmin@vulnprint.com", "VulnPrintAdmin08$");
        completeLogin("superadmin@vulnprint.com");
    }
    
    protected void completeLogin(String email) {
        loginPage.submitLogin();
        
        page.waitForTimeout(1000);
        if (loginPage.isErrorMessageVisible()) {
            throw new RuntimeException("Login failed for " + email + ": " + loginPage.getErrorMessage());
        }

        if (loginPage.isMfaRequested()) {
            String otp = mailpit.getLatestOTP(email);
            if (otp == null) {
                throw new RuntimeException("MFA OTP was not delivered to Mailpit for " + email);
            }
            loginPage.submitOTP(otp);
        }
        
        // Wait for dashboard to load and ensure we are logged in
        page.waitForURL("**/dashboard", new Page.WaitForURLOptions().setTimeout(15000));
        page.waitForLoadState(com.microsoft.playwright.options.LoadState.NETWORKIDLE);
        
        // Explicit check for a dashboard element to ensure hydration
        page.waitForSelector("#add-pentest-btn", new Page.WaitForSelectorOptions().setState(com.microsoft.playwright.options.WaitForSelectorState.VISIBLE).setTimeout(10000));
    }
}
