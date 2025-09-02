package com.biezbardis.thoughtyusers.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;
import java.time.format.DateTimeFormatter;

@Configuration
public class TimeConfig {
    protected static final String DATE_TIME_FORMAT = "yyyy-MM-dd HH:mm:ss.SSS";

    @Bean
    public DateTimeFormatter customDateTimeFormatter() {
        return DateTimeFormatter.ofPattern(DATE_TIME_FORMAT);
    }

    @Bean
    public Clock clock() {
        return Clock.systemDefaultZone();
    }
}
