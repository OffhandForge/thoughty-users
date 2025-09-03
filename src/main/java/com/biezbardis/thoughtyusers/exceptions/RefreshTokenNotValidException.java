package com.biezbardis.thoughtyusers.exceptions;

public class RefreshTokenNotValidException extends RuntimeException {
    public RefreshTokenNotValidException(String message) {
        super(message);
    }
}
