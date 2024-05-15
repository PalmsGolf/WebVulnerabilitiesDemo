package com.javaclub.webvulnerabilitiesdemo.filters;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collections;

public class DummyAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final String username = "user";
        final String password = "password";

        return new UsernamePasswordAuthenticationToken(
                username,
                password,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return DummyAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
