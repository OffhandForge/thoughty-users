package com.biezbardis.thoughtyusers.configuration;

import com.biezbardis.thoughtyusers.service.LoginAttemptService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class LoginRateLimitFilter extends OncePerRequestFilter {
    @Value("${api.base-path}")
    private String basePath;

    private final LoginAttemptService loginAttemptService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if ((basePath + "/login").equals(request.getRequestURI()) && "POST".equalsIgnoreCase(request.getMethod())) {

            String username = extractUsername(request);
            if (username != null && loginAttemptService.isBlocked(username)) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType("application/json");
                response.getWriter().write("{\"error\": \"Too many login attempts. Try again later.\"}");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractUsername(HttpServletRequest request) {
        try {
            String body = request.getReader().lines().collect(Collectors.joining());
            ObjectMapper mapper = new ObjectMapper();
            JsonNode node = mapper.readTree(body);
            return node.get("username").asText();
        } catch (Exception e) {
            return null;
        }
    }
}
