package com.biezbardis.thoughtyusers.service;

import com.biezbardis.thoughtyusers.dto.RefreshTokenRequest;

public interface RefreshTokenService {
    int REFRESH_TOKEN_LIFE = 1000 * 60 * 60 * 24 * 7; // 1 week;

    /**
     * Refresh token generation
     *
     * @param username user data
     * @return refresh token
     */
    String generateTokenForUser(String username);

    /**
     * Refresh access token based on refresh token
     * It is used to obtain new access token when old is expired
     *
     * @param request with access and refresh tokens
     * @return new access token
     */
    String refreshAccessToken(RefreshTokenRequest request);

    /**
     * Refresh token validation check
     *
     * @param token    refresh token
     * @param username user data
     * @return true, if token is valid
     */
    boolean isTokenValid(String token, String username);

    void revoke(String token);
}
