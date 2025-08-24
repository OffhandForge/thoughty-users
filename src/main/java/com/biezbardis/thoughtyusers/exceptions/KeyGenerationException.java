package com.biezbardis.thoughtyusers.exceptions;

public class KeyGenerationException extends RuntimeException {
    public KeyGenerationException(String message) {
        super(message);
    }

    public KeyGenerationException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
