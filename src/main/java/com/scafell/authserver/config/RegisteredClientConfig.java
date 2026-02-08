package com.scafell.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import javax.sql.DataSource;
import java.time.Duration;
import java.util.UUID;

@Configuration
public class RegisteredClientConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {

        // =================================================================
        // CONFIDENTIAL CLIENT (for server-side applications)
        // =================================================================
        // Use this for:
        // - Backend services
        // - Server-side web applications
        // - Applications that can securely store secrets
        // =================================================================

         RegisteredClient confidentialClient = RegisteredClient.withId(UUID.randomUUID().toString())
                // Client identifier (public, sent in requests)
                .clientId("demo-client")
             // ✅ CRITICAL: Properly encode the secret
                // NEVER use {noop} even in development
                .clientSecret(passwordEncoder.encode("demo-secret"))
               // How the client authenticates to the token endpoint
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                
                // Supported OAuth2 flows
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                 // Where to redirect after authorization
                // ✅ IMPORTANT: These should point to YOUR client application
                .redirectUri("http://localhost:8080/login/oauth2/code/demo-client")
                .redirectUri("http://localhost:8080/authorized")
                
                // Scopes this client can request
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .scope("read")
                .scope("write")

              // Client-specific settings
                .clientSettings(ClientSettings.builder()
                        // Require user to approve scopes (consent screen)
                        .requireAuthorizationConsent(true)
                        // PKCE not required for confidential clients (they have secrets)
                        .requireProofKey(false)
                        .build())
             
             // Token lifetime and refresh behavior
                .tokenSettings(TokenSettings.builder()
                        // Access token expires in 30 minutes
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        // Refresh token expires in 1 day
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        // ✅ BEST PRACTICE: Issue new refresh token on each refresh
                        // This provides better security and allows for token rotation detection
                        .reuseRefreshTokens(false)
                        .build())
                
                .build();


        
        // =================================================================
        // PUBLIC CLIENT (for SPAs, mobile apps, desktop apps)
        // =================================================================
        // Use this for:
        // - Single Page Applications (React, Angular, Vue)
        // - Mobile applications (iOS, Android)
        // - Desktop applications
        // - Any client that cannot securely store secrets
        // =================================================================
        RegisteredClient publicClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("public-client")
                
                // ✅ Public clients have NO secret (cannot be kept secure)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                
                // Only authorization code flow (with PKCE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                
                .redirectUri("http://localhost:8080/login/oauth2/code/public-client")
                .redirectUri("http://localhost:8080/authorized")
                
                // Typically fewer scopes for public clients
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("read")
                
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        // ✅ CRITICAL: PKCE is REQUIRED for public clients
                        // This protects against authorization code interception attacks
                        .requireProofKey(true)
                        .build())
                
                .tokenSettings(TokenSettings.builder()
                        // ✅ Shorter token lifetime for public clients
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .refreshTokenTimeToLive(Duration.ofHours(12))
                        .reuseRefreshTokens(false)
                        .build())
                
                .build();

        // =================================================================
        // MACHINE-TO-MACHINE CLIENT (for service accounts)
        // =================================================================
        // Use this for:
        // - Microservices communication
        // - Batch jobs
        // - Background services
        // - Any non-user-facing application
        // =================================================================
        RegisteredClient m2mClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("service-account")
                .clientSecret(passwordEncoder.encode("service-secret"))
                
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                
                // Only client credentials grant (no user involved)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                
                // No redirect URI needed (no user authorization flow)
                
                // Service-specific scopes
                .scope("api.read")
                .scope("api.write")
                .scope("service.process")
                
                .clientSettings(ClientSettings.builder()
                        // No consent needed (no user involved)
                        .requireAuthorizationConsent(false)
                        .requireProofKey(false)
                        .build())
                
                .tokenSettings(TokenSettings.builder()
                        // Longer lifetime for service accounts is acceptable
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        // No refresh tokens for client credentials flow
                        .build())
                
                .build();

        // Return repository with all clients
        return new InMemoryRegisteredClientRepository(
                confidentialClient, 
                publicClient, 
                m2mClient
        );

    }

    @Bean
public RegisteredClientRepository registeredClientRepository(
        JdbcTemplate jdbcTemplate,
        PasswordEncoder passwordEncoder) {
    
    JdbcRegisteredClientRepository repository = 
        new JdbcRegisteredClientRepository(jdbcTemplate);
    
    // Check if client already exists
    if (repository.findByClientId("your-client-id") == null) {
        // Register your client programmatically
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("your-client-id")
                .clientSecret(passwordEncoder.encode("your-client-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:8080/authorized")
                .scope("read")
                .scope("write")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .reuseRefreshTokens(false)
                        .build())
                .build();
        
        repository.save(client);
    }
    
    return repository;
}

   /*
    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client")
                .clientSecret("{noop}demo-secret") // use PasswordEncoder in prod
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://localhost:9010/login/oauth2/code/google")
                .scope(OidcScopes.OPENID)
                .scope("read")
                .scope("profile")
                .scope("email")
                .scope("write")
                .build();

        return new InMemoryRegisteredClientRepository(client);
    }  */

    /*
       in production use JDBC instead of in-memory client

    */

  /*  @Bean
    RegisteredClientRepository registeredClientRepository(DataSource dataSource) {
        return new JdbcRegisteredClientRepository(dataSource);
    }*/
}
