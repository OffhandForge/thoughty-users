package com.biezbardis.thoughtyauth.service;

import com.biezbardis.thoughtyauth.dto.AuthenticationRequest;
import com.biezbardis.thoughtyauth.dto.RegisterRequest;
import com.biezbardis.thoughtyauth.entity.Role;
import com.biezbardis.thoughtyauth.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {
    @Mock
    private UserService userService;
    @Mock
    private JwtService jwtService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private AuthenticationManager authManager;
    @InjectMocks
    private AuthenticationService service;

    private UserDetails userDetails;
    private AuthenticationRequest authenticationRequest;
    private RegisterRequest registerRequest;

    @BeforeEach
    void setUp() {
        userDetails = new User(
                100500L,
                "test_user",
                "test_pass",
                "test_user@email.com",
                Role.ROLE_ADMIN
        );

        authenticationRequest = new AuthenticationRequest();
        authenticationRequest.setUsername("test_user");
        authenticationRequest.setPassword("test_pass");

        registerRequest = new RegisterRequest();
        registerRequest.setUsername("test_user");
        registerRequest.setPassword("test_pass");
        registerRequest.setEmail("test_user@email.com");
    }

    @Test
    void register() {

    }

    @Test
    void login() {

    }
}