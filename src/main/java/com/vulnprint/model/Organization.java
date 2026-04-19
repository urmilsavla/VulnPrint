package com.vulnprint.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "organization_details")
@Data
public class Organization {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String name;
    private String address;
    private String phone;
    private String email;
    
    @Column(columnDefinition = "TEXT")
    private String logo;
}
