package com.biezbardis.thoughtyusers.service;

import com.biezbardis.thoughtyusers.entity.User;
import com.biezbardis.thoughtyusers.exceptions.AlreadyInUseException;
import com.biezbardis.thoughtyusers.exceptions.UnauthorizedException;
import com.biezbardis.thoughtyusers.repository.jpa.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository repository;

    @Override
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

    @Override
    public User getByUsername(String username) {
        return repository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @Override
    public UserDetailsService userDetailsService() {
        return this::getByUsername;
    }

    @Override
    public User getCurrentUser() {
        Authentication auth = null;
        try {
            auth = SecurityContextHolder.getContext().getAuthentication();
        } catch (NullPointerException e) {
            log.error("An error occurred", e);
            throw new UnauthorizedException(e);
        }
        return getByUsername(auth.getName());
    }

    private User save(User user) {
        return repository.save(user);
    }
}
