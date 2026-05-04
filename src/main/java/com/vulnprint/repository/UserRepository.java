package com.vulnprint.repository;

import com.vulnprint.model.Role;
import com.vulnprint.model.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @EntityGraph(attributePaths = {"role", "role.permissions", "extraPermissions"})
    Optional<User> findByUsername(String username);
    
    Optional<User> findByUsernameAndPassword(String username, String password);
    List<User> findAllByRole(Role role);
}
