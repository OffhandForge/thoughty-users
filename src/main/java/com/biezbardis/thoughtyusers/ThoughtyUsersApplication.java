package com.biezbardis.thoughtyusers;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ThoughtyUsersApplication {
    @Value("${api.base-path}")
    public static final String API_BASE_PATH = "${api.base-path}";

    public static void main(String[] args) {
        SpringApplication.run(ThoughtyUsersApplication.class, args);
    }
}
