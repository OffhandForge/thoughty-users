package com.biezbardis.thoughtyauth.service;

import com.biezbardis.thoughtyauth.entity.Role;
import com.biezbardis.thoughtyauth.entity.User;
import com.biezbardis.thoughtyauth.exceptions.AlreadyInUseException;
import com.biezbardis.thoughtyauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository repository;

    /**
     * User storing
     *
     * @return saved user
     */
    public User save(User user) {
        return repository.save(user);
    }

    /**
     * User creation
     *
     * @return created user
     */
    public User create(User user) {
        if (repository.existsByUsername(user.getUsername())) {
            String message = String.format("Username \"%s\" is already in use", user.getUsername());
            throw new AlreadyInUseException(message);
        }

        if (repository.existsByEmail(user.getEmail())) {
            String message = String.format("Email \"%s\" is already in use", user.getEmail());
            throw new AlreadyInUseException(message);
        }

        return save(user);
    }

    /**
     * Get user by username
     *
     * @return user
     */
    public User getByUsername(String username) {
        return repository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

    }

    /**
     * Get user by username
     * <p>
     * Need for Spring Security
     *
     * @return user
     */
    public UserDetailsService userDetailsService() {
        return this::getByUsername;
    }

    /**
     * Get current user
     *
     * @return current user
     */
    public User getCurrentUser() {
        var username = SecurityContextHolder.getContext().getAuthentication().getName();
        return getByUsername(username);
    }

    /**
     * Granting administrator rights to the current user
     * <p>
     * Need for demo
     */
    @Deprecated
    public void getAdmin() {
        var user = getCurrentUser();
        user.setRole(Role.ROLE_ADMIN);
        save(user);
    }
}
