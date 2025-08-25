package com.biezbardis.thoughtyusers.exceptions;

public class UnauthorizedException extends RuntimeException {
    public UnauthorizedException(Throwable ex) {
        super(ex);
    }

    public UnauthorizedException(String message) {
        super(message);
    }

    public UnauthorizedException(String message, Throwable ex) {
        super(message, ex);
    }
}
