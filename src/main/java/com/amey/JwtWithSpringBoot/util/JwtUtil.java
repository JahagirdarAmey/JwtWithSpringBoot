package com.amey.JwtWithSpringBoot.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.stream.Collectors;

public class JwtUtil {
    public static String generateToken(User user, boolean isAccessToken) {
        Algorithm algorithm = getAlgorithm();

        if (isAccessToken) {
            return JWT
                    .create()
                    .withSubject(user.getUsername())
                    .withExpiresAt(new java.util.Date(System.currentTimeMillis() + 1000 * 60 * 60))
                    .withIssuer("http://localhost:8080/")
                    .withClaim("role", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                    .sign(algorithm);

        } else {
            return JWT
                    .create()
                    .withSubject(user.getUsername())
                    .withExpiresAt(new java.util.Date(System.currentTimeMillis() + 1000 * 60 * 60))
                    .withIssuer("http://localhost:8080/")
                    .sign(algorithm);

        }


    }

    public static Algorithm getAlgorithm() {
        return Algorithm.HMAC256("secret".getBytes());
    }

    public static JWTVerifier getJWTVerifier(Algorithm algorithm) {
        return JWT.require(algorithm).build();
    }
}
