package com.biezbardis.thoughtyusers.service;

import com.biezbardis.thoughtyusers.dto.AuthenticationRequest;
import com.biezbardis.thoughtyusers.dto.AuthenticationResponse;
import com.biezbardis.thoughtyusers.dto.RegisterRequest;
import com.biezbardis.thoughtyusers.entity.Role;
import com.biezbardis.thoughtyusers.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;

    /**
     * Registration request
     *
     * @param request user data
     * @return access and refresh tokens
     */
    public AuthenticationResponse register(RegisterRequest request) {

        var user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.ROLE_USER)
                .build();

        userService.create(user);

        var accessToken = jwtService.generateAccessToken(user);
        var refreshToken = refreshTokenService.generateTokenForUser(user);
        return new AuthenticationResponse(accessToken, refreshToken);
    }

    /**
     * User authentication
     *
     * @param request user data
     * @return access and refresh tokens
     */
    public AuthenticationResponse login(AuthenticationRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getUsername(),
                request.getPassword()
        ));

        UserDetails user;
        try {
            user = userService.userDetailsService().loadUserByUsername(request.getUsername());
        } catch (UsernameNotFoundException e) {
            throw new BadCredentialsException("Bad credentials");
        }

        var accessToken = jwtService.generateAccessToken(user);
        var refreshToken = refreshTokenService.generateTokenForUser(user);
        return new AuthenticationResponse(accessToken, refreshToken);
    }
}