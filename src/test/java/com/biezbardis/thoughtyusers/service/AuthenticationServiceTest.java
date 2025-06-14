package com.biezbardis.thoughtyusers.service;

import com.biezbardis.thoughtyusers.dto.AuthenticationRequest;
import com.biezbardis.thoughtyusers.dto.RegisterRequest;
import com.biezbardis.thoughtyusers.entity.Role;
import com.biezbardis.thoughtyusers.entity.User;
import com.biezbardis.thoughtyusers.exceptions.AlreadyInUseException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtService jwtService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private UserDetails userDetails;
    @Mock
    private UserDetailsService userDetailsService;
    @Mock
    private UserService userService;
    @InjectMocks
    private AuthenticationService authenticationService;

    private RegisterRequest regRequest;
    private AuthenticationRequest authRequest;

    @BeforeEach
    void setUp() {
        regRequest = new RegisterRequest();
        regRequest.setUsername("test_user");
        regRequest.setEmail("test@example.com");
        regRequest.setPassword("plainPassword");

        authRequest = new AuthenticationRequest();
        authRequest.setUsername("test_user");
        authRequest.setPassword("plainPassword");

        userDetails = new User(
                1L,
                regRequest.getUsername(),
                regRequest.getPassword(),
                regRequest.getEmail(),
                Role.ROLE_ADMIN
        );
    }

    @Test
    void register_ShouldCreateUserAndReturnAccessToken() {
        String encodedPassword = "encodedPassword";
        String expectedAccessToken = "access-token";

        User expectedUser = User.builder()
                .username(regRequest.getUsername())
                .email(regRequest.getEmail())
                .password(encodedPassword)
                .role(Role.ROLE_USER)
                .build();

        when(passwordEncoder.encode(regRequest.getPassword())).thenReturn(encodedPassword);
        when(jwtService.generateAccessToken("test_user")).thenReturn(expectedAccessToken);

        var token = authenticationService.register(regRequest);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userService).create(userCaptor.capture());
        User actualUser = userCaptor.getValue();

        assertEquals(expectedUser.getUsername(), actualUser.getUsername());
        assertEquals(expectedUser.getEmail(), actualUser.getEmail());
        assertEquals(expectedUser.getPassword(), actualUser.getPassword());
        assertEquals(expectedUser.getRole(), actualUser.getRole());

        assertEquals(expectedAccessToken, token);
    }

    @Test
    void register_ShouldThrowExceptionWhenUsernameAlreadyExists() {
        when(passwordEncoder.encode(anyString())).thenReturn("encoded");
        doThrow(new AlreadyInUseException("Username already exists"))
                .when(userService).create(any(User.class));

        assertThrows(AlreadyInUseException.class, () -> authenticationService.register(regRequest));
    }

    @Test
    void login_ShouldReturnTokenWhenCredentialsAreValid() {
        String accessToken = "access-token";
        var authToken = new UsernamePasswordAuthenticationToken(
                userDetails.getUsername(),
                userDetails.getPassword()
        );

        when(authenticationManager.authenticate(authToken)).thenReturn(authToken);
        when(jwtService.generateAccessToken(userDetails.getUsername())).thenReturn(accessToken);

        var token = authenticationService.login(authRequest);

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(jwtService).generateAccessToken(userDetails.getUsername());

        assertEquals(accessToken, token);
    }

    @Test
    void login_ShouldThrowExceptionWhenAuthenticationFails() {
        doThrow(new BadCredentialsException("Bad credentials"))
                .when(authenticationManager)
                .authenticate(any(UsernamePasswordAuthenticationToken.class));

        assertThrows(BadCredentialsException.class, () -> authenticationService.login(authRequest));
    }

    @Test
    void login_ShouldThrowExceptionWhenUserNotFound() {
        when(authenticationManager.authenticate(any()))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        var thrown = assertThrows(BadCredentialsException.class, () -> authenticationService.login(authRequest));
        assertEquals("Bad credentials", thrown.getMessage());
    }
}