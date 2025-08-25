package com.biezbardis.thoughtyusers.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
@Schema(description = "Refresh Token renewal request")
public class RefreshTokenRequest {

    @Schema(description = "Expired access token", example = "eyJhxxx...")
    @NotBlank(message = "Access token cannot be empty")
    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$",
            message = "Invalid token format")
    private String accessToken;
}
