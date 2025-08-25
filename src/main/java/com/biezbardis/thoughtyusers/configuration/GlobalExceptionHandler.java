package com.biezbardis.thoughtyusers.configuration;

import com.biezbardis.thoughtyusers.dto.ErrorResponse;
import com.biezbardis.thoughtyusers.exceptions.AlreadyInUseException;
import com.biezbardis.thoughtyusers.exceptions.KeyGenerationException;
import com.biezbardis.thoughtyusers.exceptions.RefreshTokenNotFoundException;
import com.biezbardis.thoughtyusers.exceptions.ResourceNotFoundException;
import com.biezbardis.thoughtyusers.exceptions.TooManyAttemptsException;
import com.biezbardis.thoughtyusers.exceptions.UnauthorizedException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    // --- Specific Handlers with unique responses ---
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFoundException(ResourceNotFoundException ex, WebRequest request) {
        return createErrorResponse(HttpStatus.NOT_FOUND, "Resource Not Found", ex.getMessage(), request);
    }

    @ExceptionHandler(AlreadyInUseException.class)
    public ResponseEntity<ErrorResponse> handleAlreadyInUseException(AlreadyInUseException ex, WebRequest request) {
        return createErrorResponse(HttpStatus.CONFLICT, "Already In Use", ex.getMessage(), request);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException ex, WebRequest request) {
        return createErrorResponse(HttpStatus.BAD_REQUEST, "Illegal Argument Provided", ex.getMessage(), request);
    }

    @ExceptionHandler(RefreshTokenNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleRefreshTokenNotFoundException(RefreshTokenNotFoundException ex, WebRequest request) {
        return createErrorResponse(HttpStatus.BAD_REQUEST, "Refresh Token Not Found", ex.getMessage(), request);
    }

    @ExceptionHandler(TooManyAttemptsException.class)
    public ResponseEntity<ErrorResponse> handleTooManyAttemptsException(TooManyAttemptsException ex, WebRequest request) {
        return createErrorResponse(HttpStatus.FORBIDDEN, "Too Many Attempts", ex.getMessage(), request);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationException(AuthenticationException ex, WebRequest request) {
        log.error(ex.getMessage(), ex);
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Unauthorized", "Authorization failed.", request);
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ErrorResponse> handleUnauthorizedException(UnauthorizedException ex, WebRequest request) {
        log.error(ex.getMessage(), ex);
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred.", request);
    }

    // --- Consolidated and Shared Handlers ---
    @ExceptionHandler(KeyGenerationException.class)
    public ResponseEntity<ErrorResponse> handleInternalServerErrors(KeyGenerationException ex, WebRequest request) {
        log.error(ex.getMessage(), ex);
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred.", request);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationExceptions(MethodArgumentNotValidException ex, WebRequest request) {

        Map<String, List<String>> errors = ex.getBindingResult().getFieldErrors().stream()
                .collect(Collectors.groupingBy(
                        FieldError::getField,
                        Collectors.mapping(fe -> {
                                    String message = fe.getDefaultMessage();
                                    return (message != null) ? message : "Validation error message not available";
                                },
                                Collectors.toList()
                        )));

        ErrorResponse errorDetails = new ErrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                "Validation Failed",
                errors,
                request.getDescription(false)
        );

        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGlobalException(Exception ex, WebRequest request) {
        log.error(ex.getMessage(), ex);
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred.", request);
    }

    private ResponseEntity<ErrorResponse> createErrorResponse(HttpStatus status, String error, Object message, WebRequest request) {
        ErrorResponse errorDetails = new ErrorResponse(
                status.value(),
                error,
                message,
                request.getDescription(false)
        );
        return new ResponseEntity<>(errorDetails, status);
    }
}