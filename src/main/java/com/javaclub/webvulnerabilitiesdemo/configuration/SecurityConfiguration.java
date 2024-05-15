package com.javaclub.webvulnerabilitiesdemo.configuration;

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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable).
                authorizeHttpRequests(authorizeHttp -> {
                    authorizeHttp.requestMatchers("/login", "css/styles.css").permitAll();
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
}
