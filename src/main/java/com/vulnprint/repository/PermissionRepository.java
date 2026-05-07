package com.vulnprint.repository;

import com.vulnprint.model.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.List;
import java.util.Collection;

public interface PermissionRepository extends JpaRepository<Permission, Long> {
    Optional<Permission> findByName(String name);
    List<Permission> findByNameIn(Collection<String> names);
}
