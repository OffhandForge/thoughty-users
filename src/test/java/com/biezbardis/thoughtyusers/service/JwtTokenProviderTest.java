package com.biezbardis.thoughtyusers.service;

import com.biezbardis.thoughtyusers.entity.Role;
import com.biezbardis.thoughtyusers.entity.User;
import com.biezbardis.thoughtyusers.utils.TestUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.KeyPair;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class JwtTokenProviderTest {

    @Mock
    private EndpointCollector endpointCollector;
    @InjectMocks
    private JwtTokenProvider jwtTokenProvider;

    private KeyPair keyPair;

    @BeforeEach
    void setup() {
        keyPair = TestUtils.getSecurityKeys();

        String privateKey = TestUtils.encodePrivateKeyToPEM(keyPair.getPrivate());
        String publicKey = TestUtils.encodePublicKeyToPEM(keyPair.getPublic());

        TestUtils.setField(jwtTokenProvider, "issuingAuthority", "test-issuer");
        TestUtils.setField(jwtTokenProvider, "workingAudience", "test-audience");
        TestUtils.setField(jwtTokenProvider, "jwtSigningPrivateKey", privateKey);
        TestUtils.setField(jwtTokenProvider, "jwtSigningPublicKey", publicKey);

        lenient().when(endpointCollector.getEndpoints()).thenReturn(
                Stream.of("POST /api/v1/login",
                                "POST /api/v1/register",
                                "POST /api/v1/refresh-token")
                        .collect(Collectors.toCollection(HashSet::new))
        );
    }

    @Test
    void generateAccessToken_ShouldContainCorrectClaims() {
        String token = jwtTokenProvider.generateAccessToken("test_user");

        Claims claims = Jwts.parser()
                .verifyWith(keyPair.getPublic())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        assertEquals("test_user", claims.getSubject());
        assertEquals("test-issuer", claims.getIssuer());
        assertTrue(((List<?>) claims.get("scopes")).contains("POST /api/v1/login"));
        assertTrue(((List<?>) claims.get("scopes")).contains("POST /api/v1/register"));
        assertTrue(((List<?>) claims.get("scopes")).contains("POST /api/v1/refresh-token"));
    }

    @Test
    void extractUserName_ShouldReturnSubject() {
        String token = jwtTokenProvider.generateAccessToken("test_user");
        assertEquals("test_user", jwtTokenProvider.extractUserName(token));
    }

    @Test
    void extractScopes_ShouldReturnScopes() {
        String token = jwtTokenProvider.generateAccessToken("test_user");
        Set<String> scopes = jwtTokenProvider.extractScopes(token);
        assertEquals(Set.of("POST /api/v1/login",
                        "POST /api/v1/register",
                        "POST /api/v1/refresh-token"),
                scopes);
    }

    @Test
    void isTokenValid_ShouldReturnTrueForCorrectUser() {
        UserDetails correctUser = User.builder()
                .username("test_user")
                .email("test_user@email.com")
                .password("test_pass")
                .role(Role.ROLE_USER)
                .build();

        String token = jwtTokenProvider.generateAccessToken("test_user");
        assertTrue(jwtTokenProvider.isTokenValid(token, correctUser));
    }

    @Test
    void isTokenValid_ShouldReturnFalseForWrongUser() {
        UserDetails wrongUser = User.builder()
                .username("wrong_user")
                .email("wrong@email.com")
                .password("test_pass")
                .role(Role.ROLE_USER)
                .build();

        String token = jwtTokenProvider.generateAccessToken("right_user");
        assertFalse(jwtTokenProvider.isTokenValid(token, wrongUser));
    }

    @Test
    void isTokenExpired_ShouldReturnTrueForExpiredToken() throws InterruptedException {
        String token = Jwts.builder()
                .issuer("test-issuer")
                .subject("test_user")
                .audience().add("test-audience").and()
                .expiration(new Date(System.currentTimeMillis() + 10)) // истечёт через 10 мс
                .signWith(keyPair.getPrivate())
                .compact();

        Thread.sleep(20); // ждём, чтобы точно протух

        assertTrue(jwtTokenProvider.isTokenExpired(token));
    }

}
