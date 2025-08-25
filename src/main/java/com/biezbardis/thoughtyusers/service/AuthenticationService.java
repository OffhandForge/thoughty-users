package com.biezbardis.thoughtyusers.service;

import com.biezbardis.thoughtyusers.dto.AuthenticationRequest;
import com.biezbardis.thoughtyusers.dto.RegisterRequest;

public interface AuthenticationService {
    /**
     * Registration request
     *
     * @param request contains username, email, and raw password
     * @return JWT access token for the newly created user
     */
    String register(RegisterRequest request);

    /**
     * User authentication
     *
     * @param request contains username, and raw password
     * @return JWT access token for the newly created user
     */
    String login(AuthenticationRequest request);
}
