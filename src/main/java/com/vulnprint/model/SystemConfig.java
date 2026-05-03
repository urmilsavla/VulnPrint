package com.vulnprint.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "system_configs")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SystemConfig {
    @Id
    private String configKey;
    
    @Column(columnDefinition = "TEXT")
    private String configValue;
}
