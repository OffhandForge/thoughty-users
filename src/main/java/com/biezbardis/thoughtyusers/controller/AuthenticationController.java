package com.biezbardis.thoughtyusers.controller;

import com.biezbardis.thoughtyusers.dto.AuthenticationRequest;
import com.biezbardis.thoughtyusers.dto.AuthenticationResponse;
import com.biezbardis.thoughtyusers.dto.RegisterRequest;
import com.biezbardis.thoughtyusers.service.AuthenticationService;
import com.biezbardis.thoughtyusers.service.RefreshTokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

@RestController
@RequestMapping("${api.base-path}")
@RequiredArgsConstructor
@Tag(name = "Authentication")
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    private final RefreshTokenService refreshTokenService;

    @Operation(summary = "User is registering")
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody @Valid RegisterRequest request,
                                                           HttpServletResponse response) {
        String accessToken = authenticationService.register(request);
        response.addHeader(HttpHeaders.SET_COOKIE, getResponseCookie(request.getUsername()));
        return new ResponseEntity<>(new AuthenticationResponse(accessToken), HttpStatus.CREATED);
    }

    @Operation(summary = "User is logging")
    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody @Valid AuthenticationRequest request,
                                                        HttpServletResponse response) {
        String accessToken = authenticationService.login(request);
        response.addHeader(HttpHeaders.SET_COOKIE, getResponseCookie(request.getUsername()));
        return ResponseEntity.ok(new AuthenticationResponse(accessToken));
    }

    private String getResponseCookie(String username) {
        String refreshToken = refreshTokenService.generateTokenForUser(username);
        return ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)
                .secure(true)
                .path("/api/v1/refresh-token")
                .sameSite("Strict")
                .maxAge(Duration.ofMillis(RefreshTokenService.REFRESH_TOKEN_LIFE))
                .build().toString();
    }
}