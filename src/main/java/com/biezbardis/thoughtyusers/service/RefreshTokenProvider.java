package com.biezbardis.thoughtyusers.service;

import com.biezbardis.thoughtyusers.entity.RefreshToken;
import com.biezbardis.thoughtyusers.entity.User;
import com.biezbardis.thoughtyusers.exceptions.RefreshTokenNotFoundException;
import com.biezbardis.thoughtyusers.repository.redis.RefreshTokenRepository;
import com.biezbardis.thoughtyusers.repository.jpa.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenProvider implements RefreshTokenService {
    @Value("${token.issuer}")
    private String issuingAuthority;
    @Value("${token.audience}")
    private String workingAudience;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    @Override
    public String generateTokenForUser(String username) {
        RefreshToken token = RefreshToken.builder()
                .username(username)
                .issuer(issuingAuthority)
                .audience(workingAudience)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_LIFE))
                .build();

        return refreshTokenRepository.save(token).getId().toString();
    }

    @Override
    public String refreshAccessToken(String accessToken, String refreshToken) {
        String userName = jwtService.extractUserName(accessToken);
        if (userName == null) {
            throw new IllegalArgumentException("Access token has no subject");
        }

        User user = userRepository.findByUsername(userName)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + userName));

        if (!isTokenValid(refreshToken, user.getUsername())) {
            revoke(refreshToken);
            throw new IllegalStateException("Refresh token is no longer valid");
        }

        return jwtService.generateAccessToken(user.getUsername());
    }

    @Override
    public boolean isTokenValid(String token, String username) {
        Date now = new Date(System.currentTimeMillis());
        UUID uuid = UUID.fromString(token);
        RefreshToken refreshToken = refreshTokenRepository.findById(uuid)
                .orElseThrow(() -> new RefreshTokenNotFoundException("Refresh token not found"));

        boolean isUserValid = refreshToken.getUsername().equals(username);
        boolean isIssuerValid = refreshToken.getIssuer().equals(issuingAuthority);
        boolean isAudienceValid = refreshToken.getAudience().equals(workingAudience);
        boolean isIssuedBeforeNow = refreshToken.getIssuedAt().before(now);
        boolean isExpired = refreshToken.getExpiration().before(now);

        return isUserValid
                && isIssuerValid
                && isAudienceValid
                && isIssuedBeforeNow
                && !isExpired;
    }

    @Override
    public void revoke(String token) {
        refreshTokenRepository.deleteById(UUID.fromString(token));
    }
}
