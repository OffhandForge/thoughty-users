package com.biezbardis.thoughtyusers.exceptions;

public class AlreadyInUseException extends RuntimeException {
    public AlreadyInUseException(String message) {
        super(message);
    }
}