package com.dev.ln.services;

import com.dev.ln.models.User;
import com.dev.ln.repository.UserRepository;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.smallrye.jwt.auth.principal.JWTParser;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotAuthorizedException;
import io.smallrye.jwt.build.Jwt;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.time.Duration;
import java.util.Map;
import java.util.Set;

@ApplicationScoped
public class UserService {

    @Inject
    JWTParser parser;
    @Inject
    UserRepository userRepository;

    public Map<String, String> login(String username, String password) {

        User user = userRepository.findByUsername(username).orElseThrow(() -> new NotAuthorizedException("Invalid credentials"));
        if (!BcryptUtil.matches(password, user.password)) {
            throw new NotAuthorizedException("Invalid credentials");
        }

        String accessToken = Jwt.issuer("ibp-chat")
                .upn(user.username)
                .groups(Set.of(user.role))
                .expiresIn(Duration.ofHours(1))
                .sign();
        String refreshToken = Jwt.issuer("ibp-chat")
                .upn(user.username)
                .groups(Set.of(user.role))
                .expiresIn(Duration.ofDays(7)).claim("refresh", true)
                .sign();

        return Map.of("accessToken", accessToken, "refreshToken", refreshToken);
    }

    public Map<String, String> refreshToken(String refreshToken) {
        try {
            JsonWebToken jwt = parser.parse(refreshToken);

            if (!jwt.getClaim("type").equals("refresh")) {
                throw new NotAuthorizedException("Invalid token");
            }

            String newAccessToken = Jwt
                    .issuer("ibp-chat")
                    .subject(jwt.getSubject())
                    .groups(jwt.getGroups())
                    .expiresIn(Duration.ofHours(1))
                    .sign();

            String newRefreshToken = Jwt
                    .issuer("ibp-chat")
                    .subject(jwt.getSubject())
                    .groups(jwt.getGroups())
                    .expiresIn(Duration.ofDays(7))
                    .claim("refresh", true)
                    .sign();
            return Map.of("accessToken", newAccessToken);

        } catch (Exception e) {
            throw new NotAuthorizedException("Invalid token");
        }
    }
}
