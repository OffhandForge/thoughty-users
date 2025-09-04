package com.biezbardis.thoughtyusers.configuration;

import com.biezbardis.thoughtyusers.entity.User;
import com.biezbardis.thoughtyusers.service.JwtService;
import com.biezbardis.thoughtyusers.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final String TOKEN_PREFIX = "Bearer ";
    private static final String HEADER_NAME = "Authorization";

    private final JwtService jwtService;
    private final UserService userService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader(HEADER_NAME);

        if (isInvalidHeader(authHeader)) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwt = authHeader.substring(TOKEN_PREFIX.length());
        String username = jwtService.extractUserName(jwt);

        if (StringUtils.isNotBlank(username) && isAuthenticationAbsent()) {
            authenticateUser(username, jwt, request);
        }

        filterChain.doFilter(request, response);
    }

    private boolean isInvalidHeader(String authHeader) {
        return StringUtils.isBlank(authHeader) || !authHeader.startsWith(TOKEN_PREFIX);
    }

    private boolean isAuthenticationAbsent() {
        return SecurityContextHolder.getContext().getAuthentication() == null;
    }

    private void authenticateUser(String username, String jwt, HttpServletRequest request) {
        log.info("Authenticating user {}", username);
        User user = userService.getByUsername(username);

        if (jwtService.isTokenValid(jwt, user) && isScopeValid(jwt, request)) {
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    user,
                    null,
                    user.getAuthorities()
            );
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authToken);
            SecurityContextHolder.setContext(context);
            log.info("Successfully authenticated user {}", username);
        }
    }

    private boolean isScopeValid(String jwt, HttpServletRequest request) {
        String contextPath = request.getContextPath() == null ? "" : request.getContextPath();
        String normalizedPath = request.getRequestURI().substring(contextPath.length());
        String required = request.getMethod() + " " + normalizedPath;
        return jwtService.extractScopes(jwt).contains(required);
    }
}
