package com.biezbardis.thoughtyusers.service;

import com.biezbardis.thoughtyusers.dto.RefreshTokenRequest;
import com.biezbardis.thoughtyusers.dto.RefreshTokenResponse;
import org.springframework.security.core.userdetails.UserDetails;

public interface RefreshTokenService {
    /**
     * Refresh token generation
     *
     * @param userDetails user data
     * @return refresh token
     */
    String generateTokenForUser(UserDetails userDetails);

    /**
     * Refresh access token based on refresh token
     * It is used to obtain new access token when old is expired
     *
     * @param request with access and refresh tokens
     * @return AuthenticationResponse
     */
    RefreshTokenResponse refreshAccessToken(RefreshTokenRequest request);

    /**
     * Refresh token validation check
     *
     * @param token       refresh token
     * @param userDetails user data
     * @return true, if token is valid
     */
    boolean isTokenValid(String token, UserDetails userDetails);

    void revoke(String token);
}
