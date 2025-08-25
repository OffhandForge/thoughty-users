package com.biezbardis.thoughtyusers.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Refresh Token renewal request")
public class RefreshTokenRequest {

    @Schema(description = "Expired access token", example = "eyJhxxx...")
    @NotBlank(message = "Access token cannot be empty")
    private String accessToken;
}
