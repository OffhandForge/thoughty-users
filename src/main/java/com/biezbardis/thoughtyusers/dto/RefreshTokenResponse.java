package com.biezbardis.thoughtyusers.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
@Schema(description = "Access token renewal request")
public class RefreshTokenResponse {

    @Schema(description = "New access token", example = "eyJhxxx...")
    @NotBlank(message = "Access token cannot be empty")
    private String accessToken;
}
