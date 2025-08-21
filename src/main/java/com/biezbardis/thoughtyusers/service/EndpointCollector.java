package com.biezbardis.thoughtyusers.service;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class EndpointCollector {

    private static final Pattern API_VERSIONED_PATH = Pattern.compile("^/api/v\\d+.*");

    private final RequestMappingHandlerMapping handlerMapping;

    public EndpointCollector(@NonNull @Qualifier("requestMappingHandlerMapping")
                             RequestMappingHandlerMapping handlerMapping) {
        this.handlerMapping = handlerMapping;
    }

    @Getter
    private Set<String> endpoints;

    @PostConstruct
    public void init() {
        endpoints = handlerMapping.getHandlerMethods().keySet().stream()
                .flatMap(info -> {
                    Set<RequestMethod> methods = info.getMethodsCondition().getMethods();

                    Stream<String> paths;
                    if (info.getPathPatternsCondition() != null) {
                        paths = info.getPathPatternsCondition().getPatterns().stream()
                                .map(Object::toString);
                    } else if (info.getPatternsCondition() != null) {
                        paths = info.getPatternsCondition().getPatterns().stream();
                    } else {
                        paths = Stream.empty();
                    }

                    return paths
                            .filter(path -> API_VERSIONED_PATH.matcher(path).matches())
                            .flatMap(path ->
                                    (methods.isEmpty() ? Stream.of("ANY") : methods.stream().map(RequestMethod::name))
                                            .map(method -> method + " " + path)
                            );
                })
                .collect(Collectors.toSet());
    }
}
