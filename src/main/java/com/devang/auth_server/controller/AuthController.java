package com.devang.auth_server.controller;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.devang.auth_server.models.RefreshTokens;
import com.devang.auth_server.models.Users;
import com.devang.auth_server.repos.RefreshTokenRepository;
import com.devang.auth_server.repos.UserRepository;
import com.devang.auth_server.services.AuthenticationManager;
import com.devang.auth_server.services.JwksProvider;
import com.devang.auth_server.services.TokenService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType ;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
public class AuthController {

    @Autowired
    JwksProvider jwksProvider;

    @Autowired
    AuthenticationManager authManager;

    @Autowired
    UserRepository userRepo;

    @Autowired
    RefreshTokenRepository refreshTokenRepo;

    @PostMapping("/register")
    public HttpStatus register(@RequestBody Users user) {
        return HttpStatus.NO_CONTENT;
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
        
        //authenticate krliya
        if (!authManager.authenticate(username, password)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        //DB se user fetch kro
        Users currentUser = userRepo.findByUsername(username);
        RefreshTokens token = userRepo.findTokenByUserId(currentUser.getId());
        
        //signing refresh token to cookie
        ResponseCookie refreshCookie = ResponseCookie.from(new TokenService().build_refresh_token(currentUser), token.toString())
                                                        .httpOnly(true)
                                                        .secure(true)
                                                        .sameSite("Strict")
                                                        .path("/auth/refresh")
                                                        .maxAge(Duration.ofDays(1))
                                                        .build();
        
        //access token generation
        return new TokenService().build_access_token(currentUser);
    }
    
    @PostMapping("/logout")
    public HttpStatus logout(@CookieValue RefreshTokens token) {
        refreshTokenRepo.deleteById(token.getId());
        return HttpStatus.NO_CONTENT;
    }

    @GetMapping(
        value = "/.well-known/jwks.json",
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public Map<String, Object> jwks() {
        return jwksProvider.getJwks();
    }
}