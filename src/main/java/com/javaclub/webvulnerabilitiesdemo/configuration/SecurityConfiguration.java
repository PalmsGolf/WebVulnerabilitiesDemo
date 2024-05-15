package com.javaclub.webvulnerabilitiesdemo.configuration;

import com.javaclub.webvulnerabilitiesdemo.csrf.CsrfRequestMatcher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http,
                                           final CsrfTokenRepository csrfTokenRepository,
                                           final CsrfRequestMatcher csrfRequestMatcher) throws Exception {
        //  configureCsrf(http, csrfTokenRepository, csrfRequestMatcher);
        //  configureXssProtection(http);
        //  configureCors(http);

        http.csrf(AbstractHttpConfigurer::disable);
        http.authorizeHttpRequests(authorizeHttp -> {
            authorizeHttp.requestMatchers("/login", "css/styles.css", "/submit").permitAll();
                    authorizeHttp.anyRequest().authenticated();
                }).formLogin(formLogin -> {
                    formLogin.permitAll();
                    formLogin.loginPage("/login");
                    formLogin.defaultSuccessUrl("/messages", true);
                }).logout(logoutConfigurer -> {
                    logoutConfigurer.permitAll();
                    logoutConfigurer.logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
                    logoutConfigurer.logoutSuccessUrl("/login");
                    logoutConfigurer.deleteCookies("JSESSIONID"); // Important
                }).sessionManagement(sessionManagement -> sessionManagement.sessionFixation().migrateSession());


        return http.build();
    }

    private void configureCors(final HttpSecurity http) throws Exception {
        http.cors(corsConfigurer -> {
         // corsConfigurer.disable();
            corsConfigurer.configurationSource(corsConfigurationSource());
        });
    }

    private void configureXssProtection(final HttpSecurity http) throws Exception {
        http.headers(headers ->
                headers.xssProtection(
                        xss -> xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)
                ).contentSecurityPolicy(
                        cps -> cps.policyDirectives("script-src 'self'") // rule where script can be loaded from
                ));
    }

    private void configureCsrf(final HttpSecurity http, final CsrfTokenRepository csrfTokenRepository, final CsrfRequestMatcher csrfRequestMatcher) throws Exception {
        http.csrf(httpSecurityCsrfConfigurer -> {
         // httpSecurityCsrfConfigurer.requireCsrfProtectionMatcher(csrfRequestMatcher);
            httpSecurityCsrfConfigurer.csrfTokenRepository(csrfTokenRepository);
            httpSecurityCsrfConfigurer.csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler());
        });
    }

    @Bean
    protected CsrfTokenRepository csrfTokenRepository() {
        return new HttpSessionCsrfTokenRepository();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("https://127.0.0.1"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT"));
        configuration.setAllowedHeaders(List.of("Authorization", "Cache-Control", "Content-Type"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}
