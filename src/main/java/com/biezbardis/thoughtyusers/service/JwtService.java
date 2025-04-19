package com.biezbardis.thoughtyusers.service;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.Set;

public interface JwtService {

    /**
     * Extracting scopes from the access token
     *
     * @param token access token
     * @return scopes
     */
    Set<String> extractScopes(String token);

    /**
     * Extracting username from access token
     *
     * @param token access token
     * @return username
     */
    String extractUserName(String token);

    /**
     * Access token generation
     *
     * @param username user data
     * @return access token
     */
    String generateAccessToken(String username);

    /**
     * Access token validation check
     *
     * @param token       access token
     * @param userDetails user data
     * @return true, if token is valid
     */
    boolean isTokenValid(String token, UserDetails userDetails);

    /**
     * Access token expiration check
     *
     * @param token access token
     * @return true, if token expired
     */
    boolean isTokenExpired(String token);
}
