package com.biezbardis.thoughtyusers.dto;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public record ErrorResponse(String timestamp, int status, String error, Object message, String path) {
    public Map<String, List<String>> getValidationErrors() {
        if (message instanceof Map<?, ?> rawMap) {
            try {
                @SuppressWarnings("unchecked")
                Map<String, List<String>> validationErrors = (Map<String, List<String>>) rawMap;
                return validationErrors;
            } catch (ClassCastException e) {
                return Collections.emptyMap();
            }
        }
        return Collections.emptyMap();
    }

    public boolean hasValidationErrors() {
        return message instanceof Map<?, ?>;
    }
}
