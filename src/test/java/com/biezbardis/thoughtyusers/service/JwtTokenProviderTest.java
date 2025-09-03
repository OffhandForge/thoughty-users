package com.biezbardis.thoughtyusers.service;

import com.biezbardis.thoughtyusers.entity.Role;
import com.biezbardis.thoughtyusers.entity.User;
import com.biezbardis.thoughtyusers.utils.JjwtClockAdapter;
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
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
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
    private Clock clock;
    @Mock
    private EndpointCollector endpointCollector;
    @InjectMocks
    private JwtTokenProvider jwtTokenProvider;

    private KeyPair keyPair;
    private Instant now;

    @BeforeEach
    void setup() {
        now = Instant.parse("2025-08-30T10:00:00Z");
        lenient().when(clock.instant()).thenReturn(now);
        lenient().when(clock.getZone()).thenReturn(ZoneOffset.UTC);

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
                .clock(new JjwtClockAdapter(clock))
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
    void isTokenExpired_ShouldReturnTrueForExpiredToken() {
        String token = Jwts.builder()
                .issuer("test-issuer")
                .subject("test_user")
                .audience().add("test-audience").and()
                .expiration(Date.from(now.minusSeconds(1)))
                .signWith(keyPair.getPrivate())
                .compact();

        assertTrue(jwtTokenProvider.isTokenExpired(token));
    }
}
