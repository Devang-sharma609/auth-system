package com.devang.auth_server.services;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

import org.springframework.stereotype.Component;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

@Component
public class JwksProvider {

    private final RSAKey rsaKey;

    public JwksProvider() throws Exception {
        this.rsaKey = loadPublicKey();
    }

    private RSAKey loadPublicKey() throws Exception {

        String pem = Files.readString(
                Paths.get("src/main/resources/public.pem")
        );

        String publicKeyContent = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        X509EncodedKeySpec spec = new X509EncodedKeySpec(
                Base64.getDecoder().decode(publicKeyContent)
        );

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey =
                (RSAPublicKey) keyFactory.generatePublic(spec);

        return new RSAKey.Builder(publicKey)
                .keyID("auth-rsa-2026-02")
                .algorithm(JWSAlgorithm.RS256)
                .keyUse(KeyUse.SIGNATURE)
                .build();
    }

    public Map<String, Object> getJwks() {
        return new JWKSet(rsaKey).toJSONObject();
    }
}
