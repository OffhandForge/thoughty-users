package com.biezbardis.thoughtyauth.exceptions;

public class AlreadyInUseException extends RuntimeException {
    public AlreadyInUseException(String message) {
        super(message);
    }
}