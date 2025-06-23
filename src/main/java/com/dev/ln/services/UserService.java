package com.dev.ln.services;

import com.dev.ln.models.User;
import com.dev.ln.repository.UserRepository;
import com.dev.ln.utils.RefreshRequest;
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
                .expiresIn(Duration.ofDays(7)).claim("type", "refresh")
                .sign();

        return Map.of("accessToken", accessToken, "refreshToken", refreshToken);
    }

    public Map<String, String> refreshToken(RefreshRequest request) {

        try {

            System.out.println("Token: " + request.refreshToken);
            String token = request.refreshToken;

            JsonWebToken jwt = parser.parse(token);

            if (!"refresh".equals(jwt.getClaim("type"))) {
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
                    .claim("type", "refresh")
                    .sign();
            return Map.of("accessToken", newAccessToken, "refreshToken", newRefreshToken);

        } catch (Exception e) {
            e.printStackTrace();
            throw new NotAuthorizedException("Invalid token");
        }
    }
}
