package com.biezbardis.thoughtyusers.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@Schema(description = "Registration request")
public class RegisterRequest {

    @Schema(description = "Username", example = "JohnDoe")
    @Size(min = 5, max = 50, message = "Username must be between 5 and 50 characters long")
    @NotBlank(message = "Username cannot be empty")
    @Pattern(regexp = "^[a-zA-Z0-9]([._-](?![._-])|[a-zA-Z0-9])[a-zA-Z0-9]$",
            message = "Username must start and end with alphanumeric characters and may contain digits, dot (.), underscore (_), or hyphen (-)")
    private String username;

    @Schema(description = "Email address", example = "johndoe@gmail.com")
    @Size(min = 5, max = 255, message = "Email address must be between 5 and 255 characters long")
    @NotBlank(message = "Email address cannot be empty")
    @Email(message = "Email address must be in the format user@example.com")
    @Pattern(regexp = "^[A-Za-z0-9._+-]+@[a-z0-9.-]+\\.[a-z]{2,6}$", message = "Invalid email format")
    private String email;

    @Schema(description = "Password", example = "my_1secret1_password")
    @Size(min = 8, max = 64, message = "Password length must be between 8 and 64 characters")
    @NotBlank(message = "Password cannot be empty")
    @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&-+=()])(?=\\S+$)$",
            message = "Password must contains of at least one digit, one small letter, one capital letter and one symbol")
    private String password;
}
