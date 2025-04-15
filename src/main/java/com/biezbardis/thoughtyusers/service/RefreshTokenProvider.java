package com.biezbardis.thoughtyusers.service;

import com.biezbardis.thoughtyusers.dto.RefreshTokenRequest;
import com.biezbardis.thoughtyusers.dto.RefreshTokenResponse;
import com.biezbardis.thoughtyusers.entity.RefreshToken;
import com.biezbardis.thoughtyusers.entity.User;
import com.biezbardis.thoughtyusers.exceptions.RefreshTokenNotFoundException;
import com.biezbardis.thoughtyusers.repository.RefreshTokenRepository;
import com.biezbardis.thoughtyusers.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenProvider implements RefreshTokenService {
    protected static final int REFRESH_TOKEN_LIFE = 1000 * 60 * 60 * 24 * 7; // 1 week;

    @Value("${token.issuer}")
    private String issuingAuthority;
    @Value("${token.audience}")
    private String workingAudience;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    @Override
    public String generateTokenForUser(UserDetails userDetails) {
        var token = RefreshToken.builder()
                .username(userDetails.getUsername())
                .issuer(issuingAuthority)
                .audience(workingAudience)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_LIFE))
                .build();

        return refreshTokenRepository.save(token).getId().toString();
    }

    @Override
    public RefreshTokenResponse refreshAccessToken(RefreshTokenRequest request) {
        String jwt = request.getAccessToken();
        String refreshToken = request.getRefreshToken();

        String userName = jwtService.extractUserName(jwt);
        if (userName == null) {
            throw new IllegalArgumentException("Access token has no subject");
        }

        User user = userRepository.findByUsername(userName)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + userName));

        if (!isTokenValid(refreshToken, user)) {
            revoke(refreshToken);
            throw new IllegalStateException("Refresh token is no longer valid");
        }

        return new RefreshTokenResponse(jwtService.generateAccessToken(user));
    }

    @Override
    public boolean isTokenValid(String token, UserDetails userDetails) {
        Date now = new Date(System.currentTimeMillis());
        var uuid = UUID.fromString(token);
        var refreshToken = refreshTokenRepository.findById(uuid)
                .orElseThrow(() -> new RefreshTokenNotFoundException("Refresh token not found"));

        boolean isUserValid = refreshToken.getUsername().equals(userDetails.getUsername());
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
