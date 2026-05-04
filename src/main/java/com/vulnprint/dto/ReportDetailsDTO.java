package com.vulnprint.dto;

import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ReportDetailsDTO {
    private Boolean disclaimerEnabled;
    
    @Size(max = 10000)
    private String disclaimer;

    private Boolean executiveSummaryEnabled;
    
    @Size(max = 10000)
    private String executiveSummary;

    private Boolean methodologyEnabled;
    private String methodologyDisplayMode;
    
    @Size(max = 10000)
    private String methodology;
    
    private String methodologyImage;
    private String selectedMethodologyImages;

    private Boolean owaspEnabled;
    private String owaspTop10;
    private String selectedOwaspCategories;
    private String owaspImage;

    private Boolean riskOverviewEnabled;
    
    @Size(max = 5000)
    private String riskSummary;
    
    private String riskOverviewChart;

    private Boolean severityEnabled;
    private String severityDefinitions;

    private Boolean conclusionEnabled;
    
    @Size(max = 5000)
    private String conclusion;

    private Boolean brandingEnabled;
    private String organizationLogo;
    private String clientLogo;

    @Size(max = 255)
    private String clientName;
    @Size(max = 255)
    private String clientSpocName;
    @Size(max = 255)
    private String clientSpocContact;

    private Long reportApproverId;

    private Boolean organizationDetailsEnabled;
    @Size(max = 255)
    private String organizationName;
    @Size(max = 255)
    private String organizationLegalName;
    @Size(max = 500)
    private String organizationAddress;
    @Size(max = 50)
    private String organizationPhone;
    @Size(max = 100)
    private String organizationEmail;

    @Size(max = 255)
    private String submittedToName;
    @Size(max = 255)
    private String submittedToDesignation;
}
