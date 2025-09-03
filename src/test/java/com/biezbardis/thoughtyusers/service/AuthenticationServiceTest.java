package com.biezbardis.thoughtyusers.service;

import com.biezbardis.thoughtyusers.dto.AuthenticationRequest;
import com.biezbardis.thoughtyusers.dto.RegisterRequest;
import com.biezbardis.thoughtyusers.entity.Role;
import com.biezbardis.thoughtyusers.entity.User;
import com.biezbardis.thoughtyusers.exceptions.AlreadyInUseException;
import com.biezbardis.thoughtyusers.exceptions.UnauthorizedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtService jwtService;
    @Mock
    private LoginAttemptService loginAttemptService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private UserService userService;
    @InjectMocks
    private AuthenticationServiceImpl authenticationService;

    private RegisterRequest regRequest;
    private AuthenticationRequest authRequest;

    @BeforeEach
    void setUp() {
        regRequest = new RegisterRequest();
        regRequest.setUsername("test_user");
        regRequest.setEmail("test@example.com");
        regRequest.setPassword("plainPassword");

        authRequest = new AuthenticationRequest("test_user", "plainPassword");
    }

    @Test
    void register_ShouldCreateUserAndReturnJwtToken() {
        when(passwordEncoder.encode(regRequest.getPassword())).thenReturn("encodedPassword");
        when(jwtService.generateAccessToken(regRequest.getUsername())).thenReturn("access-token");

        String actual = authenticationService.register(regRequest);

        assertEquals("access-token", actual);
        verify(passwordEncoder).encode(regRequest.getPassword());
        verify(userService).create(argThat(user ->
                user.getUsername().equals(regRequest.getUsername()) &&
                        user.getEmail().equals(regRequest.getEmail()) &&
                        user.getPassword().equals("encodedPassword") &&
                        user.getRole() == Role.ROLE_USER
        ));
        verify(jwtService).generateAccessToken(regRequest.getUsername());
    }

    @Test
    void register_ShouldUseEncodedPassword_NotRawPassword() {
        when(passwordEncoder.encode(regRequest.getPassword())).thenReturn("encodedPassword");
        when(jwtService.generateAccessToken(regRequest.getUsername())).thenReturn("access-token");

        authenticationService.register(regRequest);

        verify(userService).create(argThat(user ->
                !user.getPassword().equals(regRequest.getPassword()) &&
                        user.getPassword().equals("encodedPassword")
        ));
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
        when(jwtService.generateAccessToken(regRequest.getUsername())).thenReturn(expectedAccessToken);

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
        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
        doThrow(new AlreadyInUseException("Username already exists"))
                .when(userService).create(any(User.class));

        assertThrows(AlreadyInUseException.class, () -> authenticationService.register(regRequest));
    }

    @Test
    void login_ShouldReturnJwtToken_WhenAuthenticationSuccessful() {
        Authentication auth = mock(Authentication.class);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(auth);
        when(auth.getName()).thenReturn(authRequest.getUsername());
        when(jwtService.generateAccessToken(authRequest.getUsername())).thenReturn("access-token");

        String token = authenticationService.login(authRequest);

        assertEquals("access-token", token);
        verify(loginAttemptService).loginSucceeded(authRequest.getUsername());
        verify(jwtService).generateAccessToken(authRequest.getUsername());
    }

    @Test
    void login_ShouldThrowUnauthorizedException_WhenAuthenticationFails() {
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(mock(AuthenticationException.class));

        UnauthorizedException ex = assertThrows(UnauthorizedException.class,
                () -> authenticationService.login(authRequest));

        assertEquals("Invalid credentials", ex.getMessage());
        verify(loginAttemptService).loginFailed(authRequest.getUsername());
        verify(jwtService, never()).generateAccessToken(anyString());
    }
}