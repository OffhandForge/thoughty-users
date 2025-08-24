package com.biezbardis.thoughtyusers.dto;

import java.time.LocalDateTime;

public record ErrorResponse(String timestamp, int status, String error, Object message, String path) {
    public ErrorResponse(int status, String error, Object message, String path) {
        this(LocalDateTime.now().toString(), status, error, message, path);
    }
}
