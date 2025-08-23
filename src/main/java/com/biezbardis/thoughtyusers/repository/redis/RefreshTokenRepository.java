package com.biezbardis.thoughtyusers.repository.redis;

import com.biezbardis.thoughtyusers.entity.RefreshToken;
import org.springframework.data.keyvalue.repository.KeyValueRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends KeyValueRepository<RefreshToken, UUID> {
}
