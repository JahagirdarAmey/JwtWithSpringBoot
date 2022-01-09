package com.amey.JwtWithSpringBoot.service;

import com.amey.JwtWithSpringBoot.domain.AppUser;
import com.amey.JwtWithSpringBoot.domain.Role;
import com.amey.JwtWithSpringBoot.repository.AppUserRepository;
import com.amey.JwtWithSpringBoot.repository.RoleRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;

@Service
@AllArgsConstructor
@Transactional
public class APIService  {

    private final RoleRepository roleRepository;
    private final AppUserRepository appUserRepository;


    public AppUser saveUser(AppUser appUser) {
        return appUserRepository.save(appUser);
    }

    public Role saveRole(Role role) {
        return roleRepository.save(role);
    }

    public void addRoleToUser(String aUser, String aRole) {
        AppUser appUser = appUserRepository.findByUsername(aUser);
        Role role = roleRepository.findByName(aRole);
        appUser.getRoles().add(role);
        appUserRepository.save(appUser);
    }

    public AppUser getUser(String username) {
        return appUserRepository.findByUsername(username);
    }

    public List<AppUser> getAllUsers() {
        return appUserRepository.findAll();
    }

}
