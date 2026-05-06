package com.vulnprint.repository;

import com.vulnprint.model.UserSession;
import com.vulnprint.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.UUID;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, UUID> {
    List<UserSession> findAllByUserAndRevokedFalse(User user);
    void deleteByUser(User user);
}
