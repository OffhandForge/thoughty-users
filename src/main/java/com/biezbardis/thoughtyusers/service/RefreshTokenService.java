package com.biezbardis.thoughtyusers.service;

/**
 * Service implementation for managing refresh tokens.
 * <p>
 * Responsibilities:
 * <ul>
 *   <li>Generate and persist refresh tokens for users</li>
 *   <li>Validate refresh tokens against stored data</li>
 *   <li>Revoke refresh tokens</li>
 *   <li>Generate new access tokens using valid refresh tokens</li>
 * </ul>
 *
 * <p>
 * This implementation uses a persistent store via {@link com.biezbardis.thoughtyusers.repository.redis.RefreshTokenRepository}
 * to ensure refresh tokens survive application restarts and can be revoked
 * individually.
 * </p>
 */
public interface RefreshTokenService {
    int REFRESH_TOKEN_LIFE = 1000 * 60 * 60 * 24 * 7; // 1 week;

    /**
     * Generates and persists a new refresh token for the given user.
     *
     * @param username the username for which to generate the token
     * @return the generated refresh token ID (UUID as a string)
     */
    String generateTokenForUser(String username);

    /**
     * Generates a new access token for the user, provided that the given
     * refresh token is valid.
     *
     * @param accessToken  the current (possibly expired) access token
     * @param refreshToken the refresh token to validate
     * @return a newly generated access token
     * @throws IllegalArgumentException if the access token does not contain a subject
     * @throws org.springframework.security.core.userdetails.UsernameNotFoundException if the user cannot be found in the repository
     * @throws IllegalStateException if the refresh token is invalid
     */
    String refreshAccessToken(String accessToken, String refreshToken);

    /**
     * Validates a refresh token against stored data and expected values.
     *
     * @param token    the refresh token UUID (as string)
     * @param username the username that should match the token
     * @return {@code true} if the token is valid, {@code false} otherwise
     * @throws com.biezbardis.thoughtyusers.exceptions.RefreshTokenNotFoundException if the token is not found in the repository
     */
    boolean isTokenValid(String token, String username);

    /**
     * Revokes (deletes) a refresh token from the repository.
     *
     * @param token the refresh token UUID (as string)
     */
    void revoke(String token);
}
