package com.vulnprint.controller;

import com.vulnprint.repository.PentestRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class ViewController {

    @Autowired
    private PentestRepository pentestRepository;

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard() {
        return "dashboard";
    }

    @GetMapping("/web-pentest")
    public String webPentest(Model model) {
        model.addAttribute("type", "Web");
        return "pentest-list";
    }

    @GetMapping("/mobile-pentest")
    public String mobilePentest(Model model) {
        model.addAttribute("type", "Mobile");
        return "pentest-list";
    }

    @GetMapping("/pentest/add")
    public String addPentest() {
        return "add-pentest";
    }

    @GetMapping("/pentest/edit/{id}")
    public String editPentest(@PathVariable Long id, Model model) {
        model.addAttribute("id", id);
        return "add-pentest";
    }

    @GetMapping("/api-pentest")
    public String apiPentest(Model model) {
        model.addAttribute("type", "API");
        return "pentest-list";
    }

    @GetMapping("/network-pentest")
    public String networkPentest(Model model) {
        model.addAttribute("type", "Network");
        return "pentest-list";
    }

    @GetMapping("/source-code-pentest")
    public String sourceCodePentest(Model model) {
        model.addAttribute("type", "Source Code");
        return "pentest-list";
    }

    @GetMapping("/pentest/details/{id}")
    public String pentestDetails(@PathVariable Long id, Model model) {
        model.addAttribute("id", id);
        return "pentest-detail";
    }

    @GetMapping("/pentest/report-designer/{id}")
    public String reportDesigner(@PathVariable Long id, Model model) {
        model.addAttribute("id", id);
        return "report-designer";
    }

    @GetMapping("/template-guide")
    public String templateGuide() {
        return "report-mapping-docs";
    }

    @GetMapping("/pentest/{id}/vulnerability/add")
    public String addVulnerability(@PathVariable Long id, Model model) {
        model.addAttribute("id", id);
        return "add-vulnerability";
    }

    @GetMapping("/pentest/{pentestId}/vulnerability/edit/{vulnId}")
    public String editVulnerability(@PathVariable Long pentestId, @PathVariable Long vulnId, Model model) {
        model.addAttribute("id", pentestId);
        model.addAttribute("vulnId", vulnId);
        return "add-vulnerability"; // We can reuse the same form for edit
    }

    @GetMapping("/user-management")
    public String userManagement() {
        return "user-management";
    }

    @GetMapping("/organization-settings")
    public String organizationSettings() {
        return "organization-settings";
    }

    @GetMapping("/profile")
    public String profile() {
        return "profile";
    }

    @GetMapping("/microservice-management")
    public String microserviceManagement() {
        return "microservice-management";
    }

    @GetMapping("/generate-report")
    public String generateReport() {
        return "generate-report";
    }

    @GetMapping("/reset-password")
    public String resetPassword() {
        return "reset-password";
    }

    @GetMapping("/")
    public String index() {
        return "redirect:/login";
    }
}
