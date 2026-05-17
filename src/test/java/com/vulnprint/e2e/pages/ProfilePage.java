package com.vulnprint.e2e.pages;

import com.microsoft.playwright.Page;

public class ProfilePage {
    private final Page page;

    public ProfilePage(Page page) {
        this.page = page;
    }

    public void navigateToMyProfile() {
        page.click("#user-menu-button");
        page.click("text=My Profile");
    }

    public void updateAddress(String address) {
        page.fill("#profile-address", address);
        page.click("button:has-text('Update Profile')");
    }

    public boolean isSuccessMessageVisible() {
        return page.isVisible("text=successfully");
    }
}
