package com.biezbardis.thoughtyusers.utils;

import io.jsonwebtoken.Jwts;

import java.lang.reflect.Field;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class TestUtils {
    public static KeyPair getSecurityKeys() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


    public static void setField(Object target, String fieldName, Object value) {
        try {
            Field field = target.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String encodePrivateKeyToPEM(PrivateKey privateKey) {
        return "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(privateKey.getEncoded()) +
                "\n-----END PRIVATE KEY-----";
    }

    public static String encodePublicKeyToPEM(PublicKey publicKey) {
        return "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getEncoder().encodeToString(publicKey.getEncoded()) +
                "\n-----END PUBLIC KEY-----";
    }

    public static Date getExpiration(PublicKey publicKey, String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration();
    }

    public static String generateExpiredAccessToken(String username,
                                             PrivateKey privateKey,
                                             String issuingAuthority,
                                             String workingAudience,
                                             List<String> scopes) {
        long oneHourInThePast = 3600 * 1000L;

        return Jwts.builder()
                .issuer(issuingAuthority)
                .subject(username)
                .audience().add(workingAudience).and()
                .issuedAt(new Date(System.currentTimeMillis() - oneHourInThePast))
                .expiration(new Date(System.currentTimeMillis() - oneHourInThePast))
                .claims(Map.of("scopes", scopes))
                .signWith(privateKey)
                .compact();
    }
}
