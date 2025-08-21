package com.biezbardis.thoughtyusers.configuration;

import com.biezbardis.thoughtyusers.service.LoginAttemptService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;

@RequiredArgsConstructor
public class LoginRateLimitFilter extends OncePerRequestFilter {

    private final LoginAttemptService loginAttemptService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if ("/api/v1/login".equals(request.getRequestURI()) && "POST".equalsIgnoreCase(request.getMethod())) {

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
        if (!(request instanceof ContentCachingRequestWrapper wrapper)) {
            return null;
        }
        try {
            byte[] buf = wrapper.getContentAsByteArray();
            if (buf.length == 0) {
                return null;
            }
            String body = new String(buf, request.getCharacterEncoding());
            ObjectMapper mapper = new ObjectMapper();
            JsonNode node = mapper.readTree(body);
            return node.has("username") ? node.get("username").asText() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
