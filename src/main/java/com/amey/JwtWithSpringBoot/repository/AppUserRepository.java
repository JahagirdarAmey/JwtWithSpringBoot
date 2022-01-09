package com.amey.JwtWithSpringBoot.repository;

import com.amey.JwtWithSpringBoot.domain.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);



}
