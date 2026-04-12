package com.vulnprint.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "alerts")
@Data
public class Alert {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String level; // Critical, High, System
    private String title; // This will hold the XSS payload
    private String details;
    private String timeAgo;
}
