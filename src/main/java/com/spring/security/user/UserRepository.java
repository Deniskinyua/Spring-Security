package com.spring.security.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
//9.
public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByEmail(String email);
}
