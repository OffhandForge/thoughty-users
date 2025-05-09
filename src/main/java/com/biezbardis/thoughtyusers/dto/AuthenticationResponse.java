package com.biezbardis.thoughtyusers.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "Response with access token")
public class AuthenticationResponse {

    @Schema(description = "Access token", example = "eyJhxxx...")
    private String accessToken;
}
