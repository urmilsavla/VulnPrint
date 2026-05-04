package com.vulnprint.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class OrganizationDTO {
    private Long id;
    
    @NotBlank(message = "Name is required")
    private String name;
    
    private String legalName;
    private String address;
    private String phone;
    
    @Email(message = "Invalid email format")
    private String email;
    
    private String logo;
}
