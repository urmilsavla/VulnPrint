package com.vulnprint.controller;

import com.vulnprint.repository.PentestRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import org.springframework.security.access.prepost.PreAuthorize;

@Controller
public class ViewController {

    @Autowired
    private PentestRepository pentestRepository;

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/dashboard")
    @PreAuthorize("hasAuthority('VIEW_DASHBOARD')")
    public String dashboard() {
        return "dashboard";
    }

    @GetMapping("/web-pentest")
    @PreAuthorize("hasAuthority('VIEW_ASSIGNED_PROJECTS') or hasAuthority('VIEW_ALL_PROJECTS')")
    public String webPentest(Model model) {
        model.addAttribute("type", "Web");
        return "pentest-list";
    }

    @GetMapping("/mobile-pentest")
    @PreAuthorize("hasAuthority('VIEW_ASSIGNED_PROJECTS') or hasAuthority('VIEW_ALL_PROJECTS')")
    public String mobilePentest(Model model) {
        model.addAttribute("type", "Mobile");
        return "pentest-list";
    }

    @GetMapping("/pentest/add")
    @PreAuthorize("hasAuthority('ADD_PROJECT')")
    public String addPentest() {
        return "add-pentest";
    }

    @GetMapping("/pentest/edit/{id}")
    @PreAuthorize("hasAuthority('EDIT_ALL_PROJECTS') or (hasAuthority('EDIT_ASSIGNED_PROJECTS') and @securityService.isAssignedToPentest(#id))")
    public String editPentest(@PathVariable Long id, Model model) {
        model.addAttribute("id", id);
        return "add-pentest";
    }

    @GetMapping("/api-pentest")
    @PreAuthorize("hasAuthority('VIEW_ASSIGNED_PROJECTS') or hasAuthority('VIEW_ALL_PROJECTS')")
    public String apiPentest(Model model) {
        model.addAttribute("type", "API");
        return "pentest-list";
    }

    @GetMapping("/network-pentest")
    @PreAuthorize("hasAuthority('VIEW_ASSIGNED_PROJECTS') or hasAuthority('VIEW_ALL_PROJECTS')")
    public String networkPentest(Model model) {
        model.addAttribute("type", "Network");
        return "pentest-list";
    }

    @GetMapping("/source-code-pentest")
    @PreAuthorize("hasAuthority('VIEW_ASSIGNED_PROJECTS') or hasAuthority('VIEW_ALL_PROJECTS')")
    public String sourceCodePentest(Model model) {
        model.addAttribute("type", "Source Code");
        return "pentest-list";
    }

    @GetMapping("/pentest/details/{id}")
    @PreAuthorize("hasAuthority('VIEW_ALL_PROJECTS') or @securityService.isAssignedToPentest(#id)")
    public String pentestDetails(@PathVariable Long id, Model model) {
        model.addAttribute("id", id);
        return "pentest-detail";
    }

    @GetMapping("/pentest/report-designer/{id}")
    @PreAuthorize("hasAuthority('MANAGE_REPORT_DESIGN') and (hasAuthority('EDIT_ALL_PROJECTS') or @securityService.isAssignedToPentest(#id))")
    public String reportDesigner(@PathVariable Long id, Model model) {
        model.addAttribute("id", id);
        return "report-designer";
    }

    @GetMapping("/template-guide")
    @PreAuthorize("hasAuthority('VIEW_DASHBOARD')")
    public String templateGuide() {
        return "report-mapping-docs";
    }

    @GetMapping("/pentest/{id}/vulnerability/add")
    @PreAuthorize("hasAuthority('ADD_VULNERABILITY') and (hasAuthority('VIEW_ALL_PROJECTS') or @securityService.isAssignedToPentest(#id))")
    public String addVulnerability(@PathVariable Long id, Model model) {
        model.addAttribute("id", id);
        return "add-vulnerability";
    }

    @GetMapping("/pentest/{pentestId}/vulnerability/edit/{vulnId}")
    @PreAuthorize("hasAuthority('EDIT_ALL_VULNS') or (hasAuthority('EDIT_ASSIGNED_VULNS') and @securityService.isAssignedToVuln(#vulnId))")
    public String editVulnerability(@PathVariable Long pentestId, @PathVariable Long vulnId, Model model) {
        model.addAttribute("id", pentestId);
        model.addAttribute("vulnId", vulnId);
        return "add-vulnerability"; // We can reuse the same form for edit
    }

    @GetMapping("/vulnerability-approver")
    @PreAuthorize("hasAuthority('APPROVE_VULNERABILITIES')")
    public String vulnerabilityApprover() {
        return "vulnerability-approver";
    }

    @GetMapping("/user-management")
    @PreAuthorize("hasAuthority('MANAGE_USERS')")
    public String userManagement() {
        return "user-management";
    }

    @GetMapping("/organization-settings")
    @PreAuthorize("hasAuthority('MANAGE_REPORT_DESIGN')")
    public String organizationSettings() {
        return "organization-settings";
    }

    @GetMapping("/profile")
    @PreAuthorize("hasAuthority('EDIT_MY_PROFILE')")
    public String profile() {
        return "profile";
    }

    @GetMapping("/microservice-management")
    @PreAuthorize("hasAuthority('MANAGE_MICROSERVICES')")
    public String microserviceManagement() {
        return "microservice-management";
    }

    @GetMapping("/manage-access")
    @PreAuthorize("hasAuthority('MANAGE_ACCESS')")
    public String manageAccess() {
        return "manage-access";
    }

    @GetMapping("/generate-report")
    @PreAuthorize("hasAuthority('GENERATE_REPORT')")
    public String generateReport() {
        return "generate-report";
    }

    @GetMapping("/reset-password")
    @PreAuthorize("hasAuthority('RESET_PASSWORD')")
    public String resetPassword() {
        return "reset-password";
    }

    @GetMapping("/")
    public String index() {
        return "redirect:/login";
    }
}
