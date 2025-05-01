package com.biezbardis.thoughtyusers.entity;

import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.redis.core.RedisHash;

import java.io.Serializable;
import java.util.Date;
import java.util.UUID;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@RedisHash(value = "refresh_tokens", timeToLive = 60 * 60 * 24 * 7) // TTL = 7 days
public class RefreshToken implements Serializable {
    @Id
    private UUID id;

    private String username;

    private String issuer;

    private String audience;

    private Date issuedAt;

    private Date expiration;
}