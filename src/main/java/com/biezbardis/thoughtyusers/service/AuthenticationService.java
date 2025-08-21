package com.biezbardis.thoughtyusers.service;

import com.biezbardis.thoughtyusers.dto.AuthenticationRequest;
import com.biezbardis.thoughtyusers.dto.RegisterRequest;
import com.biezbardis.thoughtyusers.entity.Role;
import com.biezbardis.thoughtyusers.entity.User;
import com.biezbardis.thoughtyusers.exceptions.TooManyAttemptsException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final LoginAttemptService loginAttemptService;
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    /**
     * Registration request
     *
     * @param request contains username, email, and raw password
     * @return JWT access token for the newly created user
     */
    public String register(RegisterRequest request) {

        var user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.ROLE_USER)
                .build();

        userService.create(user);

        return jwtService.generateAccessToken(user.getUsername());
    }

    /**
     * User authentication
     *
     * @param request contains username, and raw password
     * @return JWT access token for the newly created user
     */
    public String login(AuthenticationRequest request) {
        String username = request.getUsername();

        if (loginAttemptService.isBlocked(username)) {
            throw new TooManyAttemptsException("Too many failed attempts. Try again later.");
        }

        try {
            Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    username,
                    request.getPassword()
            ));
            loginAttemptService.loginSucceeded(username);

            return jwtService.generateAccessToken(auth.getName());
        } catch (BadCredentialsException e) {
            loginAttemptService.loginFailed(username);
            throw new BadCredentialsException("Bad credentials. Try again later.");
        }
    }
}
