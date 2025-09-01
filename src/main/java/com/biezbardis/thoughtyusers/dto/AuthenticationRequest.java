package com.biezbardis.thoughtyusers.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
@Schema(description = "Authentication request")
public class AuthenticationRequest {

    @Schema(description = "Username", example = "John_Doe")
    @Size(min = 5, max = 50, message = "Username must be between 5 and 50 characters long")
    @NotBlank(message = "Username cannot be empty")
    private String username;

    @Schema(description = "Password", example = "My_1secret1_p@ssword")
    @Size(min = 8, max = 64, message = "Password length must be between 8 and 64 characters")
    @NotBlank(message = "Password cannot be empty")
    private String password;
}
