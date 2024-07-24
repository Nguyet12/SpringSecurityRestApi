package com.bootcamp.springsecurityrestapi.repository;

import com.bootcamp.springsecurityrestapi.domain.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser,Long> {
    public AppUser findByUserName(String username);
    public AppUser findByEmail(String email);
}
