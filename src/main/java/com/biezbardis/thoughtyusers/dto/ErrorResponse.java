package com.biezbardis.thoughtyusers.dto;

public record ErrorResponse(String timestamp, int status, String error, Object message, String path) {
}
