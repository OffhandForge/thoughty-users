package com.biezbardis.thoughtyusers.service;

import com.biezbardis.thoughtyusers.entity.User;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService {
    /**
     * User creation
     *
     * @return created user
     */
    User create(User user);

    /**
     * Get user by username
     *
     * @return user
     */
    User getByUsername(String username);

    /**
     * Provides UserDetailsService of the current user
     * <p>
     * Need for Spring Security
     *
     * @return current user
     */
    UserDetailsService userDetailsService();

    /**
     * Get current user
     *
     * @return current user
     */
    User getCurrentUser();
}
