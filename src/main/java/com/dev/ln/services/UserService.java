package com.dev.ln.services;

import com.dev.ln.models.User;
import com.dev.ln.repository.UserRepository;
import io.quarkus.elytron.security.common.BcryptUtil;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotAuthorizedException;
import io.smallrye.jwt.build.Jwt;

import java.time.Duration;
import java.util.Set;

@ApplicationScoped
public class UserService {

    @Inject
    UserRepository userRepository;

    public String login(String username, String password) {

        User user = userRepository.findByUsername(username).orElseThrow(() -> new NotAuthorizedException("User not found"));

        if (!BcryptUtil.matches(password, user.password)) {
            throw new NotAuthorizedException("Invalid password");
        }

        return Jwt.issuer("ibp-chat")
                .upn(user.username)
                .groups(Set.of(user.role))
                .expiresIn(Duration.ofHours(1))
                .sign();
    }
}
