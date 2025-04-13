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
            MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDP3Fc10WGWg9NF
            69dwU31/mVU5mud58L7lc4Fn8OjqYHzgZX5SZKGTuFtAMhzHcvP5rgqIGvW5nv+x
            Q2Zeym7vGpUjpV2Jr+RB4sAAkuMs2j2wx4LerevGuf9Cf4dsI+4szI86USLM0lBM
            AxhpmQ6YWP8Pr6eoNyKBVO0yKDM9gR26613AiB0qtzG2ukS+wzXonXMFEd0fO0eV
            FdQPgmnuQVBE+0oXeIhA6L0VLOm9MlA20aVlrrz96np0UQkRlLb5H0rwX5YDYhGC
            Ql8tCtKRza7QCduWXpPsQgUkVQQz4SLJLbn920UhL642VY/t7/BofLS0lNvhb7Hs
            5XkY8ujHAgMBAAECggEACcDoG5pF8MnMxj9+fF8syLge31GrXrzk6EOeCIzmnz1L
            mz1PEgg9QLgGqCG49YtiVrlLoIznwHG0UgugKDei3TC5lGD0MsnkA4Pjj6pxRr3a
            AhmuGdmFZDTUGZzTc51Cq0gmc39O7teA5xH6HPJj/0SJXS/YU9Em8Fg5u1VW6GkO
            XHtJIhle3XJVHhMrbcPrrALbFP4PovgJ8D3zBOCVgkKmHJD2SXpW/PuPhw+ZLt9m
            JESKMOnMeFVl5qyOeFi94ELzNuj1XXfC2VSXqXoPzk/fTqEFMyq4y4zLrj0JsI27
            KYrnZWV3LPuPTN7lq7+NXjYUAdE3cGI4NqH6dc1p0QKBgQD1psQupAirG9axw0ZV
            t+cITLcAikWUn4xo/D8qDyB0v6SxuOEu0FsZXVO2CBWMhczGO4qokB/wm8CNxzuY
            GKZKdgmUFV0yWH8Owu2wWcorj9gyZgDNVDdXwDQ3HcxQ4XaAdJvpUFWd1X4xTvtI
            xJv8dfu83IjVNTvl53nImmrxuQKBgQDYngT0qxfj9o/aKj3pToY4/dr18nA3W1mf
            wokfLhlouNVTPOttT/90G01RypOTGiNZFEJVezMhj5Sw7V35PFVvqBj3rcYbBeRT
            VyTfYS6oLdHCR9calOzA1Zhq/zaZH8ux4kIPsqOtGqV8df38r460p1w4UBQPpBmz
            U/FUHAPufwKBgQDOfUUxc3853efFe0D3MuQITPwTfydn/Al6AndR8m801BcrsR3Q
            TSIWmyWPwRHkEmCETW6LrMK8bSAZzVxhyG6X7sq0aJTzigIbtW05LPDNV1fDXYzV
            DDKNF6qMngauAieraNnZ8EZXqystZZfCnkoEmGRoZ/S5S8sywTXUk0DMOQKBgBi9
            a3l6NP9PQLy9CFcmJcRKkgB3EQPxhfnuIPUTsck5GvwnwAe7FETxfVIzHcm2OYVK
            AA19Rai2mlfetFXr4yIeg8N98FtTv/EYydhNZCPHH+bdh568lZGsk3zc6yJv9Da7
            zam3UGRL38yoOTrr3hOZ7blsw+3JYzoNA0oE7RoHAoGACgNBqq9AlK2T1/LQfuI8
            bzoZUiS8HVml1Jqr8vnYeGnUqezo66+tgWO55UWlmCmJNa7N/tyPbbAYrm7cO5s4
            y6GvDdoEGMKc2UxJc4VkY4VL2wGz8UjeHxOq9rLDopy114LCXtHC+n5voEe4BWWi
            lFG1Z9RwADohKPJIBR2x2/Q=
            -----END PRIVATE KEY-----
            """;

    private final String publicKey = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz9xXNdFhloPTRevXcFN9
            f5lVOZrnefC+5XOBZ/Do6mB84GV+UmShk7hbQDIcx3Lz+a4KiBr1uZ7/sUNmXspu
            7xqVI6Vdia/kQeLAAJLjLNo9sMeC3q3rxrn/Qn+HbCPuLMyPOlEizNJQTAMYaZkO
            mFj/D6+nqDcigVTtMigzPYEduutdwIgdKrcxtrpEvsM16J1zBRHdHztHlRXUD4Jp
            7kFQRPtKF3iIQOi9FSzpvTJQNtGlZa68/ep6dFEJEZS2+R9K8F+WA2IRgkJfLQrS
            kc2u0Anbll6T7EIFJFUEM+EiyS25/dtFIS+uNlWP7e/waHy0tJTb4W+x7OV5GPLo
            xwIDAQAB
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
