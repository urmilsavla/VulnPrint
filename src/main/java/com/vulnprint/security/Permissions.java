package com.vulnprint.security;

public class Permissions {
    // Projects (Pentests)
    public static final String VIEW_ASSIGNED_PROJECTS = "VIEW_ASSIGNED_PROJECTS";
    public static final String VIEW_ALL_PROJECTS = "VIEW_ALL_PROJECTS";
    public static final String ADD_PROJECT = "ADD_PROJECT";
    public static final String EDIT_ASSIGNED_PROJECTS = "EDIT_ASSIGNED_PROJECTS";
    public static final String EDIT_ALL_PROJECTS = "EDIT_ALL_PROJECTS";
    public static final String DELETE_ASSIGNED_PROJECTS = "DELETE_ASSIGNED_PROJECTS";
    public static final String DELETE_ALL_PROJECTS = "DELETE_ALL_PROJECTS";
    public static final String CHANGE_PENTEST_STATUS = "CHANGE_PENTEST_STATUS";

    // Vulnerabilities
    public static final String VIEW_ASSIGNED_VULNS = "VIEW_ASSIGNED_VULNS";
    public static final String VIEW_ALL_VULNS = "VIEW_ALL_VULNS";
    public static final String ADD_VULNERABILITY = "ADD_VULNERABILITY";
    public static final String EDIT_ASSIGNED_VULNS = "EDIT_ASSIGNED_VULNS";
    public static final String EDIT_ALL_VULNS = "EDIT_ALL_VULNS";
    public static final String DELETE_ASSIGNED_VULNS = "DELETE_ASSIGNED_VULNS";
    public static final String DELETE_ALL_VULNS = "DELETE_ALL_VULNS";
    public static final String APPROVE_ASSIGNED_VULNS = "APPROVE_ASSIGNED_VULNS";
    public static final String APPROVE_ALL_VULNS = "APPROVE_ALL_VULNS";
    
    // Status Modifiers
    public static final String CHANGE_VULN_REPORTING_STATUS = "CHANGE_VULN_REPORTING_STATUS";
    public static final String CHANGE_VULN_STATUS = "CHANGE_VULN_STATUS";

    // System & Design
    public static final String MANAGE_REPORT_DESIGN = "MANAGE_REPORT_DESIGN";
    public static final String GENERATE_REPORT = "GENERATE_REPORT";
    public static final String VIEW_DASHBOARD = "VIEW_DASHBOARD";
    public static final String VIEW_ALERTS = "VIEW_ALERTS";
    public static final String MANAGE_ALERTS = "MANAGE_ALERTS";
    public static final String VIEW_USERS = "VIEW_USERS";
    public static final String MANAGE_USERS = "MANAGE_USERS";
    public static final String MANAGE_ACCESS = "MANAGE_ACCESS";
    public static final String MANAGE_MICROSERVICES = "MANAGE_MICROSERVICES";
    public static final String EDIT_MY_PROFILE = "EDIT_MY_PROFILE";
    public static final String RESET_PASSWORD = "RESET_PASSWORD";
}
