package com.vulnprint.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class SystemConfigDTO {
    @NotBlank(message = "Config key is required")
    private String configKey;
    
    private String configValue;
}
