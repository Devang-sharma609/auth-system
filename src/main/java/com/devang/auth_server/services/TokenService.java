package com.devang.auth_server.services;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import com.devang.auth_server.models.Users;
import com.devang.auth_server.repos.UserRepository;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

@Service
public class TokenService {

    @Autowired
    UserRepository userRepo;

    private Users authUser;
    private JWTClaimsSet claims;
    private static Resource resource;
    private static RSAPrivateKey key;

    static {
        try {
            String pem = new String(
                    resource.getInputStream().readAllBytes(),
                    StandardCharsets.UTF_8);

            pem = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decoded = Base64.getDecoder().decode(pem);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            key = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public TokenService(String username) throws Exception {
        authUser = userRepo.findByUsername(username);
        String jti = UUID.randomUUID().toString();

        // building token claims
        claims = new JWTClaimsSet.Builder()
                .subject(authUser.getId().toString())
                .issuer("https://localhost:9090")
                .audience("https://localhost:8080")
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .claim("role", authUser.getRole())
                .jwtID(jti)
                .build();
    }

    public String tokenFactory() throws Exception {
        JWSSigner signer = new RSASSASigner(key);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .keyID("auth-rsa-2025-01")
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claims);

        signedJWT.sign(signer);

        return signedJWT.serialize();
    }
}
