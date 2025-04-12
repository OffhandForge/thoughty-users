package com.biezbardis.thoughtyusers.controller;

import com.biezbardis.thoughtyusers.dto.AuthenticationRequest;
import com.biezbardis.thoughtyusers.dto.RegisterRequest;
import com.biezbardis.thoughtyusers.service.AuthenticationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(MockitoExtension.class)
class AuthenticationControllerTest {
    @Mock
    private AuthenticationService authService;

    @InjectMocks
    private AuthenticationController authenticationController;

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

    // TODO fix test
//    @Test
//    void register() {
//        when(authService.register(regRequest)).thenReturn(new AuthenticationResponse("Bearer eyJhb_"));
//        var actual = authController.register(regRequest);
//        assertNotNull(actual);
//        assertEquals("Bearer eyJhb_", actual.getToken());
//    }

    // TODO Fix token
//    @Test
//    void login() {
//        when(authService.login(authRequest)).thenReturn(new AuthenticationResponse("Bearer eyJhb_"));
//        var actual = authController.login(authRequest);
//        assertNotNull(actual);
//        assertEquals("Bearer eyJhb_", actual.getToken());
//    }
}