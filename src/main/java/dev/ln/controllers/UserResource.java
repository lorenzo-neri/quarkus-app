package dev.ln.controllers;

import dev.ln.models.User;
import io.smallrye.common.constraint.NotNull;
import jakarta.annotation.security.RolesAllowed;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

@Path("/api/users")
@Consumes(MediaType.WILDCARD)
@Produces(MediaType.WILDCARD)
public class UserResource {

    @GET
    @RolesAllowed("user")
    @Path("/me")
    public String me(@Context SecurityContext securityContext) {
        return securityContext.getUserPrincipal().getName();}

    @POST
    @Path("/register")
    @Consumes(MediaType.WILDCARD)
    @Produces(MediaType.WILDCARD)
    @Transactional
    public Response create(@NotNull User user) {
        User.add(user.username, user.password, user.role);
        return Response.ok().build();
    }


}
