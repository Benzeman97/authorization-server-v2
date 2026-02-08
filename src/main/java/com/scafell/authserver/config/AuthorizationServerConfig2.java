package com.scafell.authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.boot.security.autoconfigure.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig2 {

    private final PasswordEncoder passwordEncoder;
    private final SecurityProperties securityProperties;
    private final UserDetailsService userDetailsService;

    public AuthorizationServerConfig2(PasswordEncoder passwordEncoder,
                                    SecurityProperties securityProperties,
                                    UserDetailsService userDetailsService) {
        this.passwordEncoder = passwordEncoder;
        this.securityProperties = securityProperties;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {

        // Apply default OAuth2 Authorization Server configuration
        // This replaces your old AuthorizationServerSecurityConfigurer
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // Enable OpenID Connect (if you need it)
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());

        http
            // Redirect unauthenticated users to login page
            // (equivalent to your tokenKeyAccess configuration)
            .exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            )
            // Enable OAuth2 Resource Server for token validation
            // (equivalent to your checkTokenAccess configuration)
            .oauth2ResourceServer(resourceServer -> resourceServer
                .jwt(Customizer.withDefaults())
            );

        return http.build();
    }

   /**
     * Default security for other endpoints (login page, etc.)
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults());

        return http.build();
    }


    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        // This is equivalent to: clients.jdbc(dataSource)
        // It stores clients in the database just like your old code
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
                                                           RegisteredClientRepository registeredClientRepository) {
        // This stores authorization codes, access tokens, and refresh tokens in database
        // Similar to how you had JDBC client storage
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

     /* NEW APPROACH (4.0.2):
     * Instead of JwtAccessTokenConverter, we use JWKSource.
     * This STILL loads your KeyStore - same security.jwt.* properties work!
     * 
     * IMPORTANT: Your SecurityProperties class and application.yml don't need to change!
     */

     @Bean
    public JWKSource<SecurityContext> jwkSource() {
        SecurityProperties.JwtProperties jwtProperties = securityProperties.getJwt();
        
        try {
            // Load your existing KeyStore (same as before)
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (InputStream is = jwtProperties.getKeyStore().getInputStream()) {
                keyStore.load(is, jwtProperties.getKeyStorePassword().toCharArray());
            }
            
            // Get the key pair (same as before)
            String alias = jwtProperties.getKeyPairAlias();
            Key key = keyStore.getKey(alias, jwtProperties.getKeyPairPassword().toCharArray());
            
            if (key instanceof PrivateKey) {
                // Get the certificate and extract public key
                Certificate cert = keyStore.getCertificate(alias);
                PublicKey publicKey = cert.getPublicKey();
                
                // Convert to RSA keys
                RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
                RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) key;
                
                // Create JWK (JSON Web Key) - this is the new format
                RSAKey rsaKey = new RSAKey.Builder(rsaPublicKey)
                        .privateKey(rsaPrivateKey)
                        .keyID(UUID.randomUUID().toString())
                        .build();
                
                JWKSet jwkSet = new JWKSet(rsaKey);
                return new ImmutableJWKSet<>(jwkSet);
            }
            
            throw new IllegalStateException("Could not load key pair from KeyStore");
            
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to load JWK from KeyStore", ex);
        }
    }
  

    /**
     * JWT Decoder for validating tokens
     * This is required for OAuth2 Resource Server functionality
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

   /**
     * Authorization Server Settings
     * Configure your server's issuer URL here
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9000") // Change to your actual URL
                .build();
    }
}
