package com.biezbardis.thoughtyusers.configuration;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

@Configuration
@RequiredArgsConstructor
public class AppConfiguration {
    private final ApplicationContext applicationContext;

    @Bean
    @EventListener(ApplicationReadyEvent.class)
    public RequestMappingHandlerMapping handlerMapping() {
        return this.applicationContext.getBean(RequestMappingHandlerMapping.class);
    }
}
