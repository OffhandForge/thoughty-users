package com.biezbardis.thoughtyusers.controller;

import com.biezbardis.thoughtyusers.dto.AuthenticationResponse;
import com.biezbardis.thoughtyusers.dto.RefreshTokenRequest;
import com.biezbardis.thoughtyusers.service.RefreshTokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("${api.base-path}")
@RequiredArgsConstructor
@Tag(name = "Access token renewal", description = "Handles issuing new access tokens using refresh tokens")
public class RefreshTokenController {
    private final RefreshTokenService refreshService;

    @Operation(
            summary = "Refresh access token",
            description = "Exchanges a valid refresh token (sent as an HttpOnly cookie) and the previous access token " +
                    "for a new access token."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Access token refreshed successfully",
                    content = @Content(schema = @Schema(implementation = AuthenticationResponse.class))),
            @ApiResponse(responseCode = "401", description = "Invalid or expired refresh token"),
            @ApiResponse(responseCode = "400", description = "Invalid request payload")
    })
    @PostMapping("/refresh-token")
    public ResponseEntity<AuthenticationResponse> refreshToken(
            @Parameter(description = "Refresh token cookie set during login/register")
            @CookieValue("refresh_token") String refreshToken,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "The previous access token",
                    required = true,
                    content = @Content(schema = @Schema(implementation = RefreshTokenRequest.class))
            )
            @RequestBody @Valid RefreshTokenRequest request) {
        String accessToken = refreshService.refreshAccessToken(request.getAccessToken(), refreshToken);
        return ResponseEntity.ok(new AuthenticationResponse(accessToken));
    }
}