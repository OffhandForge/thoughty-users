package com.biezbardis.thoughtyusers.utils;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

public class JsonToObjectMapper {
    public static <T> T convert(String json, Class<T> objectClass) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, objectClass);
    }
}
