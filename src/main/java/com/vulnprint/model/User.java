package com.vulnprint.model;

import jakarta.persistence.*;
import lombok.Data;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Entity
@Table(name = "users")
@Data
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @com.fasterxml.jackson.annotation.JsonIgnore
    private String password;
    
    @Column(nullable = false, unique = true)
    private String email;
    
    private String firstName;
    private String lastName;
    
    @Enumerated(EnumType.STRING)
    private AccountStatus status = AccountStatus.ACTIVE;

    private int failedMfaAttempts = 0;
    
    @com.fasterxml.jackson.annotation.JsonIgnore
    private String mfaSecretEnc;
    
    @com.fasterxml.jackson.annotation.JsonIgnore
    private String mfaOtp;
    
    @com.fasterxml.jackson.annotation.JsonIgnore
    private java.time.LocalDateTime mfaOtpExpiry;
    private java.time.LocalDateTime accountExpiry;
    private int securityVersion = 0;

    @ManyToOne
    @JoinColumn(name = "role_id")
    private Role role;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_extra_permissions",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "permission_id")
    )
    private Set<Permission> extraPermissions = new HashSet<>();

    private String address;
    private String qualification;
    
    @Column(columnDefinition = "TEXT")
    private String profileImage;

    public String getProfileImage() {
        return (profileImage == null || profileImage.isBlank()) ? "/images/user.png" : profileImage;
    }

    private boolean enabled = true;
    private boolean deleted = false;
    private int failedLoginAttempts = 0;
    private java.time.LocalDateTime lockedUntil;
    
    @Column(name = "must_change_password", nullable = false)
    private boolean mustChangePassword = false;

    public enum AccountStatus {
        APPLIED, INVITED, MFA_PENDING, ACTIVE, LOCKED, DELETED
    }

    private java.time.LocalDateTime lastRoleChange = java.time.LocalDateTime.now();

    private String invitationToken;
    private java.time.LocalDateTime invitationExpiry;

    private String activationToken;
    private java.time.LocalDateTime tokenExpiry;

    @Override
    public String getUsername() {
        return this.email; // System ID: Email is the unique principal identifier
    }

    @Override
    public boolean isEnabled() {
        return this.enabled && !this.deleted;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        if (role != null) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));
            authorities.addAll(role.getPermissions().stream()
                    .map(p -> new SimpleGrantedAuthority(p.getName()))
                    .collect(Collectors.toList()));
        }
        if (extraPermissions != null) {
            authorities.addAll(extraPermissions.stream()
                    .map(p -> new SimpleGrantedAuthority(p.getName()))
                    .collect(Collectors.toList()));
        }
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        if (accountExpiry != null && java.time.LocalDateTime.now().isAfter(accountExpiry)) {
            return false;
        }
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        if (status == AccountStatus.LOCKED) return false;
        if (lockedUntil != null && java.time.LocalDateTime.now().isBefore(lockedUntil)) {
            return false;
        }
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
}
