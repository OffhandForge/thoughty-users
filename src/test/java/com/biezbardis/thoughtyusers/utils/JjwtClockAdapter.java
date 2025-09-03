package com.biezbardis.thoughtyusers.utils;

import io.jsonwebtoken.Clock;

import java.time.Instant;
import java.util.Date;

public class JjwtClockAdapter implements Clock {
    private final java.time.Clock javaTimeClock;

    public JjwtClockAdapter(java.time.Clock javaTimeClock) {
        this.javaTimeClock = javaTimeClock;
    }

    @Override
    public Date now() {
        return Date.from(Instant.now(javaTimeClock));
    }
}
