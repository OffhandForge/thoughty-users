package com.biezbardis.thoughtyauth.service;

import com.biezbardis.thoughtyauth.dto.AuthenticationRequest;
import com.biezbardis.thoughtyauth.dto.RegisterRequest;
import com.biezbardis.thoughtyauth.entity.Role;
import com.biezbardis.thoughtyauth.entity.User;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.File;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import static com.biezbardis.thoughtyauth.service.JwtTokenProvider.ACCESS_TOKEN_LIFE;
import static com.biezbardis.thoughtyauth.service.JwtTokenProvider.CLAIM_SCOPES;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {
    @Mock
    private UserService userService;
    @Mock
    private JwtService jwtService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private AuthenticationManager authManager;
    @InjectMocks
    private AuthenticationService service;

    private User user;
    private AuthenticationRequest authenticationRequest;
    private RegisterRequest registerRequest;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(100500L)
                .username("test_user")
                .password(passwordEncoder.encode("test_pass"))
                .email("test_user@email.com")
                .role(Role.ROLE_ADMIN)
                .build();

        authenticationRequest = new AuthenticationRequest();
        authenticationRequest.setUsername("test_user");
        authenticationRequest.setPassword("test_pass");

        registerRequest = new RegisterRequest();
        registerRequest.setUsername("test_user");
        registerRequest.setPassword("test_pass");
        registerRequest.setEmail("test_user@email.com");
    }

    @Test
    void register() {
        Date now = new Date(System.currentTimeMillis());
        Date expireAt = new Date(System.currentTimeMillis() + ACCESS_TOKEN_LIFE);
        String jwt = Jwts.builder()
                .issuer("issuer")
                .subject("test_user")
                .audience().add("audience").and()
                .issuedAt(now)
                .expiration(expireAt)
                .claims(Map.of(CLAIM_SCOPES, "POST /users-service/v1/register"))
                .signWith()
        when(userService.create(user)).thenReturn(user);
        when(jwtService.generateAccessToken(user)).thenReturn()

    }

    @Test
    void login() {

    }

    private PrivateKey getPrivateKey() {
        String key = jwtSigningPrivateKey.replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);
        var spec = new PKCS8EncodedKeySpec(keyBytes);

        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) { // TODO implement exception handler
            throw new RuntimeException(e);
        }
    }

    private PublicKey getPublicKey() {
        String key = File().replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

        try {
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) { // TODO implement exception handler
            throw new RuntimeException(e);
        }
    }

}