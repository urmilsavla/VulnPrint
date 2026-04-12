package com.vulnprint.repository;

import com.vulnprint.model.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Repository
public class UserRepository {

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * Vulnerable login method using string concatenation for SQL injection.
     */
    @SuppressWarnings("unchecked")
    public List<User> findByUsernameAndPasswordVulnerable(String username, String password) {
        String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        Query query = entityManager.createNativeQuery(sql, User.class);
        return query.getResultList();
    }

    @Transactional
    public User save(User user) {
        if (user.getId() == null) {
            entityManager.persist(user);
            return user;
        } else {
            return entityManager.merge(user);
        }
    }

    public List<User> findAll() {
        return entityManager.createNativeQuery("SELECT * FROM users", User.class).getResultList();
    }

    public Optional<User> findById(Long id) {
        return Optional.ofNullable(entityManager.find(User.class, id));
    }

    public Optional<User> findByUsername(String username) {
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        try {
            User user = (User) entityManager.createNativeQuery(sql, User.class).getSingleResult();
            return Optional.of(user);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    @Transactional
    public void deleteAll() {
        entityManager.createNativeQuery("DELETE FROM users").executeUpdate();
    }
}
