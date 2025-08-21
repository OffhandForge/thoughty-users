package com.biezbardis.thoughtyusers.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class LoginAttemptService {
    protected static final int MAX_ATTEMPT = 5;
    protected static final long ATTEMPT_RESET_MINUTES = 10;

    private final StringRedisTemplate redisTemplate;

    private String getKey(String username) {
        return "login:attempts:" + username;
    }

    public void loginFailed(String username) {
        String key = getKey(username);
        Long attempts = redisTemplate.opsForValue().increment(key);
        if (attempts != null && attempts == 1) {
            redisTemplate.expire(key, Duration.ofMinutes(ATTEMPT_RESET_MINUTES));
        }
    }

    public void loginSucceeded(String username) {
        redisTemplate.delete(getKey(username));
    }

    public boolean isBlocked(String username) {
        String key = getKey(username);
        String val = redisTemplate.opsForValue().get(key);
        if (val == null) return false;
        try {
            return Integer.parseInt(val) >= MAX_ATTEMPT;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
