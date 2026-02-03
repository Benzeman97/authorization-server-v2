package com.scafell.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class AuthorizationServerConfig{

    /*
       This creates all OAuth endpoints automatically:

         /oauth2/token
         /oauth2/authorize
         /oauth2/jwks
         /oauth2/introspect

      - Adds required OAuth2 filters internally
      - Applies CSRF, exception handling, and protocol-level security

       Why a separate filter chain?
        - OAuth endpoints have very specific security rules
        - Keeps auth-server security isolated from application security
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http){

        // Create Authorization Server configurer
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();


        // Enable OpenID Connect (OIDC 1.0)
        authorizationServerConfigurer
                .oidc(Customizer.withDefaults());

        http
                // Apply Authorization Server configuration
                .with(authorizationServerConfigurer, Customizer.withDefaults())

                // Authorization rules for OAuth endpoints
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/oauth2/jwks").permitAll()
                        .anyRequest().authenticated()
                )

                // OAuth2 endpoints must be CSRF-free
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(
                                authorizationServerConfigurer.getEndpointsMatcher()
                        )
                );

        return http.build();
    }
}