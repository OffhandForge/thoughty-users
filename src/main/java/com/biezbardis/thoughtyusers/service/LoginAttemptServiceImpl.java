package com.biezbardis.thoughtyusers.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Slf4j
@Service
@RequiredArgsConstructor
public class LoginAttemptServiceImpl implements LoginAttemptService {
    protected static final int MAX_ATTEMPT = 5;
    protected static final long ATTEMPT_RESET_MINUTES = 10;

    private final StringRedisTemplate redisTemplate;

    /**
     * Builds the Redis key used to store attempts for a specific username.
     *
     * @param username the username
     * @return the Redis key string
     */
    private String getKey(String username) {
        return "login:attempts:" + username;
    }

    @Override
    public void loginFailed(String username) {
        String key = getKey(username);
        Long attempts = redisTemplate.opsForValue().increment(key);
        if (attempts != null && attempts == 1) {
            redisTemplate.expire(key, Duration.ofMinutes(ATTEMPT_RESET_MINUTES));
        }
    }

    @Override
    public void loginSucceeded(String username) {
        log.info("Attempt succeeded for username: {}", username);
        redisTemplate.delete(getKey(username));
    }

    @Override
    public boolean isBlocked(String username) {
        String key = getKey(username);
        String val = redisTemplate.opsForValue().get(key);
        if (val == null) return false;
        try {
            return Integer.parseInt(val) >= MAX_ATTEMPT;
        } catch (NumberFormatException e) {
            log.error(e.getMessage(), e);
            return false;
        }
    }
}
