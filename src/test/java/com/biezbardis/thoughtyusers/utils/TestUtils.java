package com.biezbardis.thoughtyusers.utils;

import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.Cookie;
import org.springframework.test.web.servlet.MvcResult;

import java.lang.reflect.Field;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class TestUtils {
    private static final long ONE_HOUR_MILLIS = 3600 * 1000L;

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
        return Jwts.builder()
                .issuer(issuingAuthority)
                .subject(username)
                .audience().add(workingAudience).and()
                .issuedAt(new Date(System.currentTimeMillis() - ONE_HOUR_MILLIS))
                .expiration(new Date(System.currentTimeMillis() - ONE_HOUR_MILLIS))
                .claims(Map.of("scopes", scopes))
                .signWith(privateKey)
                .compact();
    }

    public static String createRegisterJson(TestUser user) {
        return """
                {
                  "username": "%s",
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(user.username(), user.email(), user.password());
    }

    public static String createLoginJson(String username, String password) {
        return """
                {
                  "username": "%s",
                  "password": "%s"
                }
                """.formatted(username, password);
    }

    public static String createLoginJson(TestUser user) {
        return """
                {
                  "username": "%s",
                  "password": "%s"
                }
                """.formatted(user.username(), user.password());
    }

    public static String createAccessTokenJson(String token) {
        return """
                {
                	"accessToken": "%s"
                }
                """.formatted(token);
    }

    public static Cookie getRefreshTokenCookie(MvcResult result) {
        return Arrays.stream(result.getResponse().getCookies())
                .filter(cookie -> "refresh_token".equals(cookie.getName()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Refresh token cookie not found"));
    }
}
