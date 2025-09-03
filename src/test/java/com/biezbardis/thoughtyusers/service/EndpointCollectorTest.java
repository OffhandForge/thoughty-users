package com.biezbardis.thoughtyusers.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EndpointCollectorTest {

    @Mock
    private RequestMappingHandlerMapping handlerMapping;

    private EndpointCollector endpointCollector;

    @BeforeEach
    void setUp() {
        endpointCollector = new EndpointCollector(handlerMapping);
    }

    @Test
    void init_ShouldCollectEndpoints_WithMethodsAndPaths() {
        RequestMappingInfo info = RequestMappingInfo
                .paths("/api/v1/test")
                .methods(RequestMethod.GET)
                .build();

        Map<RequestMappingInfo, HandlerMethod> map = new HashMap<>();
        map.put(info, mock(HandlerMethod.class));

        when(handlerMapping.getHandlerMethods()).thenReturn(map);

        endpointCollector.init();

        Set<String> endpoints = endpointCollector.getEndpoints();
        assertTrue(endpoints.contains("GET /api/v1/test"));
    }

    @Test
    void init_ShouldSkipNonApiVersionedPaths() {
        RequestMappingInfo info = RequestMappingInfo
                .paths("/internal/status")
                .methods(RequestMethod.GET)
                .build();

        Map<RequestMappingInfo, HandlerMethod> map = new HashMap<>();
        map.put(info, mock(HandlerMethod.class));

        when(handlerMapping.getHandlerMethods()).thenReturn(map);

        endpointCollector.init();

        Set<String> endpoints = endpointCollector.getEndpoints();
        assertFalse(endpoints.contains("GET /internal/status"));
        assertTrue(endpoints.isEmpty());
    }

    @Test
    void init_ShouldAssignAny_WhenNoHttpMethodSpecified() {
        RequestMappingInfo info = RequestMappingInfo
                .paths("/api/v2/open")
                .build();

        Map<RequestMappingInfo, HandlerMethod> map = new HashMap<>();
        map.put(info, mock(HandlerMethod.class));

        when(handlerMapping.getHandlerMethods()).thenReturn(map);

        endpointCollector.init();

        Set<String> endpoints = endpointCollector.getEndpoints();
        assertTrue(endpoints.contains("ANY /api/v2/open"));
    }
}
