package com.vulnprint.repository;

import com.vulnprint.model.Role;
import com.vulnprint.model.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @EntityGraph(attributePaths = {"role", "role.permissions", "extraPermissions"})
    @Query("SELECT u FROM User u WHERE u.email = :email AND u.deleted = false")
    Optional<User> findActiveByEmail(String email);

    @EntityGraph(attributePaths = {"role", "role.permissions", "extraPermissions"})
    @Query("SELECT u FROM User u WHERE u.email = :email AND u.deleted = false")
    Optional<User> findByEmail(String email);

    Optional<User> findByInvitationToken(String token);
    
    @Query("SELECT u FROM User u WHERE u.role = :role AND u.deleted = false")
    List<User> findAllByRole(Role role);

    @Query("SELECT u FROM User u WHERE u.deleted = false")
    List<User> findAllActive();
}
