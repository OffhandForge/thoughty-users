package com.biezbardis.thoughtyauth.controller;

import com.biezbardis.thoughtyauth.dto.JwtAuthenticationResponse;
import com.biezbardis.thoughtyauth.dto.AuthenticationRequest;
import com.biezbardis.thoughtyauth.dto.RegisterRequest;
import com.biezbardis.thoughtyauth.service.AuthenticationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication")
public class AuthController {
    private final AuthenticationService authenticationService;

    @Operation(summary = "User is registering")
    @PostMapping("/register")
    public JwtAuthenticationResponse register(@RequestBody @Valid RegisterRequest request) {
        return authenticationService.register(request);
    }

    @Operation(summary = "User is logging")
    @PostMapping("/login")
    public JwtAuthenticationResponse login(@RequestBody @Valid AuthenticationRequest request) {
        return authenticationService.login(request);
    }
}