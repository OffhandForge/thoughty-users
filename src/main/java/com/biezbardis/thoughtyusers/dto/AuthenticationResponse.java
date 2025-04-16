package com.biezbardis.thoughtyusers.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Response with access token")
public class AuthenticationResponse {

    @Schema(description = "Access token", example = "eyJhxxx...")
    private String accessToken;
}
