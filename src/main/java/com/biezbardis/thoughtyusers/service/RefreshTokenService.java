package com.biezbardis.thoughtyusers.service;

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
     * @param accessToken  old access token
     * @param refreshToken for getting new access token
     * @return new access token
     */
    String refreshAccessToken(String accessToken, String refreshToken);

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
