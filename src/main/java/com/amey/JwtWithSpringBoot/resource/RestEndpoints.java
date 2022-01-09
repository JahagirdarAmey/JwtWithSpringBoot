package com.amey.JwtWithSpringBoot.resource;

import com.amey.JwtWithSpringBoot.domain.AppUser;
import com.amey.JwtWithSpringBoot.domain.Role;
import com.amey.JwtWithSpringBoot.service.APIService;
import com.amey.JwtWithSpringBoot.util.JwtUtil;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

@RestController
@Slf4j
@AllArgsConstructor
public class RestEndpoints {

    private final APIService apiService;

    @GetMapping("/all")
    public ResponseEntity<List<AppUser>> getHello() {
        return ResponseEntity.ok().body(apiService.getAllUsers());
    }

    @GetMapping("/save/user")
    public ResponseEntity<AppUser> saveUser(@RequestBody AppUser user) {
        return ResponseEntity.ok().body(apiService.saveUser(user));
    }

    @GetMapping("/save/role")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        return ResponseEntity.ok().body(apiService.saveRole(role));
    }

    @GetMapping("/save/roletouser")
    public ResponseEntity<?> saveRoleToUser(@RequestBody RoleToUser roleToUser) {
        apiService.addRoleToUser(roleToUser.getAppUser().getUsername(), roleToUser.getRole().getName());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String token = authorizationHeader.substring("Bearer ".length());
                Algorithm algorithm = JwtUtil.getAlgorithm();

                JWTVerifier jwtVerifier = JwtUtil.getJWTVerifier(algorithm);
                DecodedJWT decodedJWT = jwtVerifier.verify(token);
                String username = decodedJWT.getSubject();
                String[] roles = decodedJWT.getClaim("roles").asArray(String.class);

                Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            } catch (Exception e) {
                e.printStackTrace();
                response.setHeader("error", "Unauthorized");
                response.setStatus(401);

                Map<String, String> error = new HashMap<>();
                error.put("error", "Unauthorized");

                response.setContentType("application/json");

                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }

        }

    }
}

@Getter
@Setter
class RoleToUser {
    private AppUser appUser;
    private Role role;
}
