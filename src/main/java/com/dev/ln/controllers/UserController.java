package com.dev.ln.controllers;

import com.dev.ln.models.User;
import com.dev.ln.models.User.Credentials;
import com.dev.ln.services.UserService;
import io.smallrye.common.constraint.NotNull;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.build.Jwt;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.time.Duration;
import java.util.Collections;
import java.util.Map;

@Path("/api/users")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class UserController {

    @Inject
    JsonWebToken jwt;

    @Inject
    UserService userService;

    @GET
    @RolesAllowed("admin")
    @Path("/me")
    public String me(@Context SecurityContext securityContext) {
        return securityContext.getUserPrincipal().getName();}

    @GET
    @RolesAllowed("admin")
    @Path("/me2")
    public String getUserData() {
        String username = jwt.getName();
        String role = jwt.getGroups().iterator().next();
        return "Ciao " + username + ", ruolo: " + role;
    }

    //SIGNIN
    @POST
    @Path("/signin")
    @Transactional
    public Response create(@NotNull User user) {
        User.add(user.username, user.password, user.role);
        return Response.ok().build();
    }

    //LOGIN
    @POST
    @Path("/login")
    public Response login(Credentials credentials) {
        Map<String, String> tokens = userService.login(credentials.username, credentials.password);
        return Response.ok(tokens).build();
    }

    //REFRESH
    @POST
    @Path("/refresh")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response refreshToken(String refreshToken) {
        if (refreshToken == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
         Map<String, String> tokens = userService.refreshToken(refreshToken);
        return Response.ok(tokens).build();
    }

}
