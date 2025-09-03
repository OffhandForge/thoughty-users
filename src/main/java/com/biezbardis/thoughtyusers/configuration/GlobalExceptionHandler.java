package com.biezbardis.thoughtyusers.configuration;

import com.biezbardis.thoughtyusers.dto.ErrorResponse;
import com.biezbardis.thoughtyusers.exceptions.AlreadyInUseException;
import com.biezbardis.thoughtyusers.exceptions.KeyGenerationException;
import com.biezbardis.thoughtyusers.exceptions.RefreshTokenNotFoundException;
import com.biezbardis.thoughtyusers.exceptions.RefreshTokenNotValidException;
import com.biezbardis.thoughtyusers.exceptions.ResourceNotFoundException;
import com.biezbardis.thoughtyusers.exceptions.TooManyAttemptsException;
import com.biezbardis.thoughtyusers.exceptions.UnauthorizedException;
import io.jsonwebtoken.JwtException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestCookieException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.time.Clock;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
@AllArgsConstructor
public class GlobalExceptionHandler {
    private DateTimeFormatter formatter;
    private final Clock clock;

    // --- Specific Handlers with unique responses ---
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFoundException(ResourceNotFoundException ex, WebRequest request) {
        log.warn("attempt to get resource failed", ex);
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

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleHttpMessageNotReadableException(HttpMessageNotReadableException ex, WebRequest request) {
        log.info("attempt to get resource failed, cause: {}", ex.getMessage());
        return createErrorResponse(HttpStatus.BAD_REQUEST, "Request Body Required", "Request body is missing or malformed.", request);
    }

    @ExceptionHandler(MissingRequestCookieException.class)
    public ResponseEntity<ErrorResponse> handleMissingRequestCookieException(MissingRequestCookieException ex, WebRequest request) {
        log.info("attempt to operate failed, cause: {}", ex.getMessage());
        return createErrorResponse(HttpStatus.BAD_REQUEST, "Cookie Required", "Cookie is not present or malformed.", request);
    }

    @ExceptionHandler(RefreshTokenNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleRefreshTokenNotFoundException(RefreshTokenNotFoundException ex, WebRequest request) {
        log.warn(ex.getMessage());
        return createErrorResponse(HttpStatus.BAD_REQUEST, "Refresh Token Required", "Invalid or expired refresh token.", request);
    }

    @ExceptionHandler(TooManyAttemptsException.class)
    public ResponseEntity<ErrorResponse> handleTooManyAttemptsException(TooManyAttemptsException ex, WebRequest request) {
        log.warn("number of attempts exceeded", ex);
        return createErrorResponse(HttpStatus.FORBIDDEN, "Too Many Attempts", ex.getMessage(), request);
    }

    @ExceptionHandler({AuthenticationException.class,
            JwtException.class,
            RefreshTokenNotValidException.class,
            UnauthorizedException.class
    })
    public ResponseEntity<ErrorResponse> handleAuthenticationException(RuntimeException ex, WebRequest request) {
        String errorMessage;
        if (ex instanceof RefreshTokenNotValidException || ex instanceof UnauthorizedException || ex instanceof JwtException) {
            errorMessage = ex.getMessage();
        } else {
            errorMessage = "An authentication error occurred.";
        }
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Unauthorized", errorMessage, request);
    }

    // --- Consolidated and Shared Handlers ---
    @ExceptionHandler(KeyGenerationException.class)
    public ResponseEntity<ErrorResponse> handleInternalServerErrors(KeyGenerationException ex, WebRequest request) {
        log.error(ex.getMessage(), ex);
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred.", request);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationExceptions(MethodArgumentNotValidException ex, WebRequest request) {
        log.info(ex.getMessage(), ex);

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
                ZonedDateTime.now(clock).format(formatter),
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
                ZonedDateTime.now(clock).format(formatter),
                status.value(),
                error,
                message,
                request.getDescription(false)
        );
        return new ResponseEntity<>(errorDetails, status);
    }
}