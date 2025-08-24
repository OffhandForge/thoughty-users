package com.biezbardis.thoughtyusers.dto;

import lombok.Data;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

@Data
public final class ErrorResponse {
    private final static DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    private final String timestamp;
    private final int status;
    private final String error;
    private final Object message;
    private final String path;

    public ErrorResponse(String timestamp, int status, String error, Object message, String path) {
        this.timestamp = timestamp;
        this.status = status;
        this.error = error;
        this.message = message;
        this.path = path;
    }

    public ErrorResponse(int status, String error, Object message, String path) {
        this(ZonedDateTime.now().format(FORMATTER), status, error, message, path);
    }
}
