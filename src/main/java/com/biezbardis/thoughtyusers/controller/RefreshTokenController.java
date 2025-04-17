package com.biezbardis.thoughtyusers.controller;

import com.biezbardis.thoughtyusers.ThoughtyUsersApplication;
import com.biezbardis.thoughtyusers.dto.AuthenticationResponse;
import com.biezbardis.thoughtyusers.dto.RefreshTokenRequest;
import com.biezbardis.thoughtyusers.service.RefreshTokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("${api.base-path}")
@RequiredArgsConstructor
@Tag(name = "Access token renewal")
public class RefreshTokenController {
    private final RefreshTokenService refreshService;

    @Operation(summary = "User is refreshing access token")
    @PostMapping("/refresh-token")
    @ResponseStatus(HttpStatus.CREATED)
    public AuthenticationResponse refreshToken(@RequestBody @Valid RefreshTokenRequest request) {
        String accessToken = refreshService.refreshAccessToken(request);
        return new AuthenticationResponse(accessToken);
    }
}