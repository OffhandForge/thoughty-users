package com.biezbardis.thoughtyusers.service;

import com.biezbardis.thoughtyusers.dto.RefreshTokenRequest;
import com.biezbardis.thoughtyusers.dto.RefreshTokenResponse;
import com.biezbardis.thoughtyusers.entity.RefreshToken;
import com.biezbardis.thoughtyusers.entity.Role;
import com.biezbardis.thoughtyusers.entity.User;
import com.biezbardis.thoughtyusers.exceptions.RefreshTokenNotFoundException;
import com.biezbardis.thoughtyusers.repository.RefreshTokenRepository;
import com.biezbardis.thoughtyusers.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import static com.biezbardis.thoughtyusers.service.RefreshTokenProvider.REFRESH_TOKEN_LIFE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefreshTokenProviderTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private JwtService jwtService;
    @InjectMocks
    private RefreshTokenProvider refreshTokenProvider;

    private UserDetails userDetails;
    private RefreshToken refreshToken;

    @BeforeEach
    void setup() {
        ReflectionTestUtils.setField(refreshTokenProvider, "issuingAuthority", "test-issuer");
        ReflectionTestUtils.setField(refreshTokenProvider, "workingAudience", "test-audience");

        userDetails = User.builder()
                .username("test-user")
                .email("test@email.com")
                .password("plain_pass")
                .role(Role.ROLE_USER)
                .build();

        refreshToken = RefreshToken.builder()
                .id(UUID.randomUUID())
                .username("test-user")
                .issuer("test-issuer")
                .audience("test-audience")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1000000))
                .build();
    }

    @Test
    void generateToken_ShouldReturnTokenForUserId_WhenUserIsValid() {
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(refreshToken);

        String result = refreshTokenProvider.generateTokenForUser(userDetails);

        assertEquals(refreshToken.getId().toString(), result);
    }

    @Test
    void refreshToken_ShouldReturnNewAccessAccessToken_WhenValid() {
        String refreshToken = UUID.randomUUID().toString();
        String accessToken = "access.jwt.token";
        String username = "test-user";

        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setAccessToken(accessToken);
        request.setRefreshToken(refreshToken);

        when(jwtService.extractUserName(accessToken)).thenReturn(username);
        when(userRepository.findByUsername(username)).thenReturn(Optional.of((User) userDetails));
        when(refreshTokenRepository.findById(UUID.fromString(refreshToken)))
                .thenReturn(Optional.of(RefreshToken.builder()
                        .id(UUID.fromString(refreshToken))
                        .username(username)
                        .issuer("test-issuer")
                        .audience("test-audience")
                        .issuedAt(new Date(System.currentTimeMillis() - 10000))
                        .expiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_LIFE))
                        .build()));
        when(jwtService.generateAccessToken(userDetails)).thenReturn("new.access.token");

        RefreshTokenResponse response = refreshTokenProvider.refreshAccessToken(request);

        assertEquals("new.access.token", response.getAccessToken());
    }

    @Test
    void refreshToken_ShouldThrowIllegalArgumentExceptionWhenAccessAccessTokenIsInvalid() {
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setAccessToken("invalid.jwt");
        request.setRefreshToken("some-refresh-token");

        when(jwtService.extractUserName("invalid.jwt")).thenReturn(null);

        var thrown = assertThrows(IllegalArgumentException.class, () ->
                refreshTokenProvider.refreshAccessToken(request));
        assertEquals("Access token has no subject", thrown.getMessage());
    }

    @Test
    void refreshAccessToken_ShouldThrowUsernameNotFoundExceptionWhenUserNotFound() {
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setAccessToken("jwt");
        request.setRefreshToken("refresh");

        when(jwtService.extractUserName("jwt")).thenReturn("ghost");
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

        var thrown = assertThrows(UsernameNotFoundException.class, () ->
                refreshTokenProvider.refreshAccessToken(request));
        assertEquals("User not found: ghost", thrown.getMessage());
    }

    @Test
    void refreshToken_ShouldRevokeAndThrowIllegalStateExceptionWhenAccessTokenIsInvalid() {
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setAccessToken("jwt");
        request.setRefreshToken(refreshToken.getId().toString());

        User user = new User();
        user.setUsername("user");

        when(jwtService.extractUserName("jwt")).thenReturn("user");
        when(userRepository.findByUsername("user")).thenReturn(Optional.of(user));
        when(refreshTokenRepository.findById(refreshToken.getId())).thenReturn(Optional.of(refreshToken));

        var thrown = assertThrows(IllegalStateException.class, () ->
                refreshTokenProvider.refreshAccessToken(request));

        assertEquals("Refresh token is no longer valid", thrown.getMessage());
        verify(refreshTokenRepository).deleteById(refreshToken.getId());
    }

    @Test
    void isTokenValid_ShouldReturnTrueWhenTokenIsValid() {
        when(refreshTokenRepository.findById(refreshToken.getId())).thenReturn(Optional.of(refreshToken));

        boolean isValid = refreshTokenProvider.isTokenValid(refreshToken.getId().toString(), this.userDetails);

        assertTrue(isValid);
    }

    @Test
    void isTokenValid_ShouldThrowRefreshTokenNotFoundExceptionWhenAccessTokenNotFound() {
        when(refreshTokenRepository.findById(refreshToken.getId())).thenReturn(Optional.empty());

        var thrown = assertThrows(RefreshTokenNotFoundException.class, () ->
                refreshTokenProvider.isTokenValid(String.valueOf(refreshToken.getId()), userDetails));
        assertEquals("Refresh token not found", thrown.getMessage());
    }

    @Test
    void revoke_ShouldDeleteTokenById() {
        refreshTokenProvider.revoke(String.valueOf(refreshToken.getId()));

        verify(refreshTokenRepository).deleteById(refreshToken.getId());
    }
}