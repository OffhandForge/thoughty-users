package com.biezbardis.thoughtyauth.controller;

import com.biezbardis.thoughtyauth.dto.AuthenticationRequest;
import com.biezbardis.thoughtyauth.dto.JwtAuthenticationResponse;
import com.biezbardis.thoughtyauth.dto.RegisterRequest;
import com.biezbardis.thoughtyauth.service.AuthenticationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {
    @Mock
    private AuthenticationService authService;

    @InjectMocks
    private AuthController authController;

    private RegisterRequest regRequest;
    private AuthenticationRequest authRequest;

    @BeforeEach
    void setUp() {
        regRequest = new RegisterRequest();
        regRequest.setUsername("test_user");
        regRequest.setPassword("test_pass");
        regRequest.setEmail("test_user@email.com");

        authRequest = new AuthenticationRequest();
        authRequest.setUsername("test_user");
        authRequest.setPassword("test_pass");
    }

    @Test
    void register() {
        when(authService.register(regRequest)).thenReturn(new JwtAuthenticationResponse("Bearer eyJhb_"));
        var actual = authController.register(regRequest);
        assertNotNull(actual);
        assertEquals("Bearer eyJhb_", actual.getToken());
    }

    @Test
    void login() {
        when(authService.login(authRequest)).thenReturn(new JwtAuthenticationResponse("Bearer eyJhb_"));
        var actual = authController.login(authRequest);
        assertNotNull(actual);
        assertEquals("Bearer eyJhb_", actual.getToken());
    }
}