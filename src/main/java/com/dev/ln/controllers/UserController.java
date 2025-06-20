package com.dev.ln.controllers;

import com.dev.ln.models.User;
import com.dev.ln.models.User.Credentials;
import com.dev.ln.services.UserService;
import io.smallrye.common.constraint.NotNull;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import java.util.Collections;

@Path("/api/users")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class UserController {

    @GET
    @RolesAllowed("user")
    @Path("/me")
    public String me(@Context SecurityContext securityContext) {
        return securityContext.getUserPrincipal().getName();}

    //SIGNIN
    @POST
    @Path("/signin")
    @Transactional
    public Response create(@NotNull User user) {
        User.add(user.username, user.password, user.role);
        return Response.ok().build();
    }

    //LOGIN
    @Inject
    UserService userService;
    @POST
    @Path("/login")
    public Response login(Credentials credentials) {
        String token = userService.login(credentials.username, credentials.password);
        System.out.println(token);
        return Response.ok(Collections.singletonMap("token", token)).build();
    }

}
