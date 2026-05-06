package com.vulnprint.model;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "user_sessions")
@Data
public class UserSession {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, length = 512)
    private String refreshTokenHash;

    private UUID parentTokenId; // For Refresh Token Rotation lineage

    private LocalDateTime expiry;
    private String ipAddress;
    private String userAgent;
    private boolean revoked = false;

    private LocalDateTime createdAt = LocalDateTime.now();
    private LocalDateTime lastActive = LocalDateTime.now();
}
