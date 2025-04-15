package com.biezbardis.thoughtyusers.configuration;

import com.biezbardis.thoughtyusers.entity.RefreshToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;

import java.time.Duration;
import java.util.UUID;

@Configuration
@EnableCaching
public class RedisConfig {
    private static final Duration TTL = Duration.ofDays(7); // Cache expiration time

//    @Value("${spring.data.redis.host}")
//    private String host;
//    @Value("${spring.data.redis.port}")
//    private int port;
//
//    @Bean
//    JedisConnectionFactory jedisConnectionFactory() {
//        RedisStandaloneConfiguration standaloneConfig = new RedisStandaloneConfiguration(host, port);
//        JedisConnectionFactory connectionFactory = new JedisConnectionFactory(standaloneConfig);
//        connectionFactory.afterPropertiesSet();
//        return connectionFactory;
//    }
//
//    @Bean
//    public RedisTemplate<UUID, RefreshToken> redisTemplate() {
//        RedisTemplate<UUID, RefreshToken> template = new RedisTemplate<>();
//        template.setConnectionFactory(jedisConnectionFactory());
//        return template;
//    }

    @Bean
    public RedisCacheConfiguration cacheConfiguration() {
        return RedisCacheConfiguration.defaultCacheConfig()
                .entryTtl(TTL)
                .disableCachingNullValues()
                .serializeValuesWith(RedisSerializationContext.SerializationPair.fromSerializer(new GenericJackson2JsonRedisSerializer()));
    }
}
