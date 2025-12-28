package com.devang.auth_server.controller;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.devang.auth_server.models.RefreshTokens;
import com.devang.auth_server.models.Users;
import com.devang.auth_server.repos.UserRepository;
import com.devang.auth_server.services.AuthenticationManager;
import com.devang.auth_server.services.TokenService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
public class AuthController {

    @Autowired
    AuthenticationManager authManager;

    @Autowired
    UserRepository userRepo;

    @PostMapping("/register")
    public HttpStatusCode register(@RequestBody Users user) {
        return HttpStatusCode.valueOf(204);
    }

    @PostMapping("/login")
    public String login(@RequestBody String loginRequestBody)
            throws Exception {

        // JSON Parse krdi
        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(loginRequestBody);

        // credentials nikaal liye authentication k liye
        String username = root.path("username").asText();
        String password = root.path("password").asText();

        if (!authManager.authenticate(username, password)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }
        Users currentUser = userRepo.findByUsername(username);
        RefreshTokens token = userRepo.findTokenByUserId(currentUser.getId());

        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", token.toString())
                                                        .httpOnly(true)
                                                        .secure(true)
                                                        .sameSite("Strict")
                                                        .path("/auth/refresh")
                                                        .maxAge(Duration.ofDays(7))
                                                        .build();

        return new TokenService(username).tokenFactory();
    }

    @PostMapping("/logout")
    public String postMethodName(@RequestBody String entity) {

        return entity;
    }

    @GetMapping("/.well-known/jwks.json")
    public String getMethodName(@RequestParam String param) {
        return new String();
    }

}
