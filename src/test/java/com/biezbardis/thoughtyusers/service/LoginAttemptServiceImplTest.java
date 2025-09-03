package com.biezbardis.thoughtyusers.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginAttemptServiceImplTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOps;

    @InjectMocks
    private LoginAttemptServiceImpl loginAttemptService;

    @BeforeEach
    void setUp() {
        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOps);
    }

    @Test
    void loginFailed_ShouldSetExpireOnFirstAttempt() {
        when(valueOps.increment("login:attempts:test-user")).thenReturn(1L);

        loginAttemptService.loginFailed("test-user");

        verify(valueOps).increment("login:attempts:test-user");
        verify(redisTemplate).expire("login:attempts:test-user",
                Duration.ofMinutes(LoginAttemptServiceImpl.ATTEMPT_RESET_MINUTES));
    }

    @Test
    void loginFailed_ShouldNotSetExpireOnSubsequentAttempts() {
        when(valueOps.increment("login:attempts:test-user")).thenReturn(2L);

        loginAttemptService.loginFailed("test-user");

        verify(valueOps).increment("login:attempts:test-user");
        verify(redisTemplate, never()).expire(anyString(), any());
    }

    @Test
    void loginSucceeded_ShouldDeleteKey() {
        loginAttemptService.loginSucceeded("test-user");
        verify(redisTemplate).delete("login:attempts:test-user");
    }

    @Test
    void isBlocked_ShouldReturnTrue_WhenAttemptsExceedMax() {
        when(valueOps.get("login:attempts:test-user"))
                .thenReturn(String.valueOf(LoginAttemptServiceImpl.MAX_ATTEMPT));

        assertTrue(loginAttemptService.isBlocked("test-user"));
    }

    @Test
    void isBlocked_ShouldReturnFalse_WhenAttemptsBelowMax() {
        when(valueOps.get("login:attempts:test-user")).thenReturn("2");

        assertFalse(loginAttemptService.isBlocked("test-user"));
    }

    @Test
    void isBlocked_ShouldReturnFalse_WhenNoValue() {
        when(valueOps.get("login:attempts:test-user")).thenReturn(null);

        assertFalse(loginAttemptService.isBlocked("test-user"));
    }

    @Test
    void isBlocked_ShouldReturnFalse_WhenValueNotANumber() {
        when(valueOps.get("login:attempts:test-user")).thenReturn("not-a-number");

        assertFalse(loginAttemptService.isBlocked("test-user"));
    }
}
