package com.vulnprint.e2e.pages;

import com.microsoft.playwright.Page;

public class LoginPage {
    private final Page page;

    public LoginPage(Page page) { this.page = page; }

    public void navigate() { page.navigate("http://localhost:8080/login"); }

    public void fillCredentials(String email, String pass) {
        page.fill("input[name='email']", email);
        page.fill("input[name='password']", pass);
    }

    public void submitLogin() { page.click("#loginForm button[type='submit']"); }

    public boolean isMfaRequested() { 
        try {
            page.waitForSelector("#mfa-tile", new com.microsoft.playwright.Page.WaitForSelectorOptions().setState(com.microsoft.playwright.options.WaitForSelectorState.VISIBLE).setTimeout(5000));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public void submitOTP(String otp) {
        page.fill("#mfaForm input[name='otp']", otp);
        page.click("#mfaForm button[type='submit']");
    }

    public boolean isErrorMessageVisible() {
        return page.isVisible("text=Invalid email or password") || page.isVisible(".toast-error");
    }

    public String getErrorMessage() {
        if (page.isVisible("text=Invalid email or password")) return "Invalid email or password";
        if (page.isVisible(".toast-error")) return page.innerText(".toast-error");
        return "Unknown Error";
    }
}
