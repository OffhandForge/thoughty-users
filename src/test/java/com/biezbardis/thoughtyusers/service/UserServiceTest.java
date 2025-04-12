package com.biezbardis.thoughtyusers.service;

import com.biezbardis.thoughtyusers.entity.Role;
import com.biezbardis.thoughtyusers.entity.User;
import com.biezbardis.thoughtyusers.exceptions.AlreadyInUseException;
import com.biezbardis.thoughtyusers.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {
    @Mock
    private Authentication authentication;
    @Mock
    private UserRepository mockUserRepository;
    @Mock
    private SecurityContext securityContext;
    @InjectMocks
    private UserServiceImpl service;

    private User user;

    @BeforeEach
    void init() {
        user = User.builder()
                .username("test_user")
                .email("test_user@email.com")
                .password("test_pass")
                .role(Role.ROLE_ADMIN)
                .build();
    }

    @Test
    void shouldSaveAndReturnUserWithAssignedIdWhenCalledCreate() {
        var expected = new User(
                1L,
                "test_user",
                "test_pass",
                "test_user@email.com",
                Role.ROLE_ADMIN);

        when(mockUserRepository.existsByUsername("test_user")).thenReturn(false);
        when(mockUserRepository.existsByEmail("test_user@email.com")).thenReturn(false);
        when(mockUserRepository.save(user)).thenReturn(expected);

        var actual = service.create(user);

        verify(mockUserRepository).save(user);
        assertNotNull(actual);
        assertEquals(expected, actual);
    }

    @Test
    void shouldThrowAlreadyInUseExceptionWhenCalledCreateWithUsername() {
        when(mockUserRepository.existsByUsername("test_user")).thenReturn(true);

        var thrown = assertThrows(AlreadyInUseException.class,
                () -> service.create(user));
        assertTrue(thrown.getMessage().contains("Username \"test_user\" is already in use"));
    }

    @Test
    void shouldThrowAlreadyInUseExceptionWhenCalledCreateWithEmail() {
        when(mockUserRepository.existsByUsername("test_user")).thenReturn(false);
        when(mockUserRepository.existsByEmail("test_user@email.com")).thenReturn(true);

        var thrown = assertThrows(AlreadyInUseException.class,
                () -> service.create(user));
        assertTrue(thrown.getMessage().contains("Email \"test_user@email.com\" is already in use"));
    }

    @Test
    void shouldReturnUserWhenCalledGetByUsernameWithExistingUsername() {
        Optional<User> expected = Optional.of(new User(
                1L,
                "test_user",
                "test_pass",
                "test_user@email.com",
                Role.ROLE_ADMIN));

        when(mockUserRepository.findByUsername("test_user")).thenReturn(expected);

        User actual = service.getByUsername("test_user");

        assertNotNull(actual);
        assertEquals(expected.get(), actual);
    }

    @Test
    void shouldThrowUsernameNotFoundExceptionWhenCalledGetByUsernameWithNonExistingUsername() {
//        when(mockUserRepository.findByUsername("test_user")).thenReturn(Optional.empty());

        var thrown = assertThrows(UsernameNotFoundException.class,
                () -> service.getByUsername("test_user"));
        assertTrue(thrown.getMessage().contains("User not found"));
    }

    @Test
    void shouldReturnCurrentUserWhenCalledGetCurrentUserAndUserExists() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getName()).thenReturn("test_user");
        when(mockUserRepository.findByUsername("test_user")).thenReturn(Optional.of(user));

        SecurityContextHolder.setContext(securityContext);

        var actual = service.getCurrentUser();

        assertNotNull(actual);
        assertEquals("test_user", actual.getUsername());
    }

    @Test
    void shouldThrowExceptionWhenCalledGetCurrentUserAndUserNotFound() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getName()).thenReturn("unknownUser");
        when(mockUserRepository.findByUsername("unknownUser")).thenReturn(Optional.empty());

        SecurityContextHolder.setContext(securityContext);

        var thrown = assertThrows(UsernameNotFoundException.class,
                () -> service.getCurrentUser());
        assertEquals("User not found", thrown.getMessage());
    }

    @Test
    void shouldReturnUserDetailsWhenCalledUserDetailsServiceAndUserExists() {
        when(mockUserRepository.findByUsername("test_user")).thenReturn(Optional.of(user));

        UserDetailsService userDetailsService = service.userDetailsService();
        UserDetails userDetails = userDetailsService.loadUserByUsername("test_user");

        verify(mockUserRepository).findByUsername("test_user");
        assertNotNull(userDetails);
        assertEquals("test_user", userDetails.getUsername());
    }

    @Test
    void shouldThrowExceptionWhenCalledUserDetailsServiceAndUserNotFound() {
        when(mockUserRepository.findByUsername("unknownUser")).thenReturn(Optional.empty());

        UserDetailsService userDetailsService = service.userDetailsService();

        var thrown = assertThrows(UsernameNotFoundException.class,
                () -> userDetailsService.loadUserByUsername("unknownUser"));
        assertTrue(thrown.getMessage().contains("User not found"));
    }
}
