package com.biezbardis.thoughtyusers.service;

import com.biezbardis.thoughtyusers.entity.Role;
import com.biezbardis.thoughtyusers.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Date;
import java.util.HashSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class JwtTokenProviderTest {

    @Mock
    private EndpointCollector endpointCollector;
    @InjectMocks
    private JwtTokenProvider jwtTokenProvider;

    private final String privateKey = """
            -----BEGIN PRIVATE KEY-----
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***=
            -----END PRIVATE KEY-----
            """;

    private final String publicKey = """
            -----BEGIN PUBLIC KEY-----
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            -----END PUBLIC KEY-----
            """;

    private User user;

    @BeforeEach
    void setup() {
        ReflectionTestUtils.setField(jwtTokenProvider, "issuingAuthority", "test-issuer");
        ReflectionTestUtils.setField(jwtTokenProvider, "workingAudience", "test-audience");
        ReflectionTestUtils.setField(jwtTokenProvider, "jwtSigningPrivateKey", privateKey);
        ReflectionTestUtils.setField(jwtTokenProvider, "jwtSigningPublicKey", publicKey);

        user = User.builder()
                .username("test_user")
                .email("test_user@email.com")
                .password("test_pass")
                .role(Role.ROLE_ADMIN)
                .build();

        lenient().when(endpointCollector.getEndpoints()).thenReturn(
                Stream.of("POST /api/v1/login",
                                "POST /api/v1/register",
                                "POST /api/v1/refresh-token")
                        .collect(Collectors.toCollection(HashSet::new))
        );
    }

    @Test
    void generateAccessToken_ShouldGenerateValidJwt() {
        String token = jwtTokenProvider.generateAccessToken(user);

        assertNotNull(token);
        String subject = jwtTokenProvider.extractUserName(token);
        assertEquals("test_user", subject);
    }

    @Test
    void isTokenValid_ShouldReturnFalse_WhenUsernameDoesNotMatch() {
        UserDetails wrongUser = User.builder()
                .username("wrong_user")
                .email("wrong@email.com")
                .password("test_pass")
                .role(Role.ROLE_USER)
                .build();

        String token = jwtTokenProvider.generateAccessToken(user);

        assertFalse(jwtTokenProvider.isTokenValid(token, wrongUser));
    }

    @Test
    void isTokenExpired_ShouldReturnTrue_ForOldToken() {
        Claims claims = Jwts.claims()
                .issuer("test-issuer")
                .subject("test-user")
                .audience().add("test-audience").and()
                .issuedAt(new Date(System.currentTimeMillis() - 3600 * 1000))
                .expiration(new Date(System.currentTimeMillis() - 1000))
                .build();

        String token = Jwts.builder()
                .claims(claims)
                .signWith(jwtTokenProvider.getPrivateKey())
                .compact();

        assertTrue(jwtTokenProvider.isTokenExpired(token));
    }
}
