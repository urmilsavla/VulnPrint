package com.vulnprint.e2e.utils;

import com.microsoft.playwright.APIRequest;
import com.microsoft.playwright.APIRequestContext;
import com.microsoft.playwright.APIResponse;
import com.microsoft.playwright.Playwright;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MailpitClient {
    private final APIRequestContext request;

    public MailpitClient(Playwright playwright) {
        this.request = playwright.request().newContext(new APIRequest.NewContextOptions()
            .setBaseURL("http://localhost:8025"));
    }

    public void clearEmails() {
        request.delete("/api/v1/messages");
    }

    public String getLatestActivationLink(String email) {
        int maxRetries = 10;
        int delayMs = 1000;

        for (int retry = 0; retry < maxRetries; retry++) {
            try { Thread.sleep(delayMs); } catch (InterruptedException e) {}

            APIResponse response = request.get("/api/v1/messages");
            if (!response.ok()) continue;
            
            JsonObject json = JsonParser.parseString(response.text()).getAsJsonObject();
            JsonArray messages = json.getAsJsonArray("messages");

            for (int i = 0; i < messages.size(); i++) {
                JsonObject msg = messages.get(i).getAsJsonObject();
                JsonArray to = msg.getAsJsonArray("To");
                if (to.toString().contains(email)) {
                    String id = msg.get("ID").getAsString();
                    APIResponse msgDetails = request.get("/api/v1/message/" + id);
                    String body = JsonParser.parseString(msgDetails.text()).getAsJsonObject().get("Text").getAsString();
                    
                    Pattern pattern = Pattern.compile("http://localhost:8080/(?:reset-password|activate-account)\\?token=[a-zA-Z0-9.-]+");
                    Matcher matcher = pattern.matcher(body);
                    if (matcher.find()) {
                        return matcher.group();
                    }
                }
            }
        }
        return null;
    }

    public String getLatestOTP(String email) {
        int maxRetries = 10;
        int delayMs = 1000;

        for (int retry = 0; retry < maxRetries; retry++) {
            try { Thread.sleep(delayMs); } catch (InterruptedException e) {}

            APIResponse response = request.get("/api/v1/messages");
            if (!response.ok()) continue;
            
            JsonObject json = JsonParser.parseString(response.text()).getAsJsonObject();
            JsonArray messages = json.getAsJsonArray("messages");

            for (int i = 0; i < messages.size(); i++) {
                JsonObject msg = messages.get(i).getAsJsonObject();
                JsonArray to = msg.getAsJsonArray("To");
                if (to.toString().contains(email)) {
                    String id = msg.get("ID").getAsString();
                    APIResponse msgDetails = request.get("/api/v1/message/" + id);
                    String body = JsonParser.parseString(msgDetails.text()).getAsJsonObject().get("Text").getAsString();
                    
                    Pattern pattern = Pattern.compile("Your verification code is: (\\d{6})");
                    Matcher matcher = pattern.matcher(body);
                    if (matcher.find()) {
                        return matcher.group(1);
                    }
                }
            }
        }
        return null;
    }
}
