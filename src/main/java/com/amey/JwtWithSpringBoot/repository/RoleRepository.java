package com.amey.JwtWithSpringBoot.repository;

import com.amey.JwtWithSpringBoot.domain.AppUser;
import com.amey.JwtWithSpringBoot.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}

