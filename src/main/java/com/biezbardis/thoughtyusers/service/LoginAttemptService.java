package com.biezbardis.thoughtyusers.service;

public interface LoginAttemptService {
    /**
     * Records a failed login attempt for the given username.
     * <p>
     * On the first failure, a TTL of 10 minutes
     * is set for the Redis entry.
     * </p>
     *
     * @param username the username of the failed attempt
     */
    void loginFailed(String username);

    /**
     * Resets the login attempts for a given username after a successful login.
     *
     * @param username the username of the successful login
     */
    void loginSucceeded(String username);

    /**
     * Checks if a given username is currently blocked due to too many failed attempts.
     *
     * @param username the username to check
     * @return {@code true} if the user has reached or exceeded 5,
     * {@code false} otherwise
     */
    boolean isBlocked(String username);
}
