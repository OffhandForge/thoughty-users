package com.biezbardis.thoughtyusers.configuration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;

public class CachingRequestFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        ContentCachingRequestWrapper wrappedRequest =
                (request instanceof ContentCachingRequestWrapper)
                        ? (ContentCachingRequestWrapper) request
                        : new ContentCachingRequestWrapper(request);

        filterChain.doFilter(wrappedRequest, response);
    }
}
