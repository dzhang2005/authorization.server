package com.oauth2.demo.authorization.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/public/**").permitAll().anyRequest().authenticated())
                .formLogin(customizer.withDefaults())
                .build();
    }
    @Bean
    public UserDetailsService userDetailsService() {
        userDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("User")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}
