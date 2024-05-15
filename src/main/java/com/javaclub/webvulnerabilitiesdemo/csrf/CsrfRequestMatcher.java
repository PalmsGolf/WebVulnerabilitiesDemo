package com.javaclub.webvulnerabilitiesdemo.csrf;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.util.UrlPathHelper;

import java.util.Set;

@Component
public class CsrfRequestMatcher implements RequestMatcher {
    private final Set<String> allowedMethods = Set.of(HttpMethod.GET.name(), HttpMethod.HEAD.name(), HttpMethod.TRACE.name(), HttpMethod.OPTIONS.name());
    private final AntPathMatcher antPathMatcher = new AntPathMatcher();
    private final UrlPathHelper urlPathHelper = new UrlPathHelper();

    @Override
    public boolean matches(final HttpServletRequest request) {
        if (this.allowedMethods.contains(request.getMethod())) {
            return false;
        }

        final String requestUri = this.urlPathHelper.getPathWithinApplication(request);

        return antPathMatcher.match("/message", requestUri);
    }
}
