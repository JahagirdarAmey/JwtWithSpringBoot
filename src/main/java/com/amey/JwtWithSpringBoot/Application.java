package com.amey.JwtWithSpringBoot;

import com.amey.JwtWithSpringBoot.domain.AppUser;
import com.amey.JwtWithSpringBoot.domain.Role;
import com.amey.JwtWithSpringBoot.service.APIService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.HashSet;

@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(APIService apiService) {
        return args -> {
            apiService.saveRole(new Role(null, "ROLE_USER"));
            apiService.saveRole(new Role(null, "ROLE_ADMIN"));

            apiService.saveUser(new AppUser(null, "Amey Jahagirdar", "amey", "amey12345", new HashSet<>()));
            apiService.saveUser(new AppUser(null, "Priyanka Jahagirdar", "priyanka", "piyu12345", new HashSet<>()));

            apiService.addRoleToUser("amey", "ROLE_USER");
            apiService.addRoleToUser("priyanka", "ROLE_ADMIN");
        };
    }
}
