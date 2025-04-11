package com.biezbardis.thoughtyauth.service;

import com.biezbardis.thoughtyauth.entity.Role;
import com.biezbardis.thoughtyauth.entity.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.SecretKey;
import java.lang.reflect.Field;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {
    private String jwtToken;

    private UserDetails testUserDetails;

    @InjectMocks
    private JwtService jwtService;

    @Spy
    private Decoder<CharSequence, byte[]> decoder = Decoders.BASE64;

    @BeforeEach
    void setUp() throws NoSuchFieldException, IllegalAccessException {
        testUserDetails = new User(
                100500L,
                "test_user",
                "test_pass",
                "test_user@email.com",
                Role.ROLE_ADMIN);

        Field signingKey = JwtTokenProvider.class.getDeclaredField("jwtSigningKey");
        signingKey.setAccessible(true);
        signingKey.set(jwtService, "My100500thVerySecretSigningKeyForJsonWebToken");

        Map<String, Object> claims = new HashMap<>();
        claims.put("id", 100500L);
        claims.put("email", "test_user@email.com");
        claims.put("role", Role.ROLE_ADMIN);

        SecretKey secretKey = Keys.hmacShaKeyFor(
                Decoders.BASE64.decode("My100500thVerySecretSigningKeyForJsonWebToken"));

        jwtToken = Jwts.builder()
                .claims(claims)
                .subject("test_user")
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // 10 hours
                .signWith(secretKey).compact();
    }

    @Test
    void shouldReturnUserNameWhenCalledExtractUserNameWithCorrectToken() {
        String actual = jwtService.extractUserName(jwtToken);

        assertEquals("test_user", actual);
    }

    @Test
    void shouldReturnGeneratedTokenWhenCalledGenerateTokenWithValidUserDetails() {
        String actual = jwtService.generateAccessToken(testUserDetails);

        assertNotNull(actual);
        assertTrue(jwtService.isTokenValid(actual, testUserDetails));
    }

    @Test
    void shouldReturnTrueWhenCalledIsTokenValidWithCorrectToken() {
        assertTrue(jwtService.isTokenValid(jwtToken, testUserDetails));
    }
}