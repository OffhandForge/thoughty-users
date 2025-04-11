package com.biezbardis.thoughtyusers.controller;

import com.biezbardis.thoughtyusers.dto.RefreshTokenRequest;
import com.biezbardis.thoughtyusers.dto.RefreshTokenResponse;
import com.biezbardis.thoughtyusers.service.RefreshTokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users-service/v1")
@RequiredArgsConstructor
@Tag(name = "Access token renewal")
public class RefreshTokenController {
    private final RefreshTokenService refreshService;

    @Operation(summary = "User is refreshing access token")
    @PostMapping("/refresh-token")
    public RefreshTokenResponse refreshToken(@RequestBody @Valid RefreshTokenRequest request) {
        return refreshService.refreshToken(request);
    }
}