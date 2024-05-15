package com.javaclub.webvulnerabilitiesdemo.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collections;

public class DummyAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    protected DummyAuthenticationFilter(final AuthenticationManager authenticationManager) {
        super(new AntPathRequestMatcher("/login", "POST"), authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response) {

        return new UsernamePasswordAuthenticationToken(
                "user",
                "password",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult)
            throws IOException {
        SecurityContextHolder.getContext().setAuthentication(authResult);

        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().print("{\"success\": true}");
        response.getWriter().flush();
    }
}
