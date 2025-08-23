package com.biezbardis.thoughtyusers.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;

@Configuration
@EnableJpaRepositories(basePackages = "com.biezbardis.thoughtyusers.repository.jpa")
@EnableRedisRepositories(basePackages = "com.biezbardis.thoughtyusers.repository.redis")
public class RepositoriesConfigurations {
}
