package com.kp.webapp.security.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepo extends JpaRepository<UserInfo, Integer> {
    //    UserInfo findByUsername(String username);
    Optional<UserInfo> findByUsername(String username);
}

