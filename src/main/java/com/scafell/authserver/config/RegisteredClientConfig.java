package com.scafell.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import javax.sql.DataSource;
import java.util.UUID;

@Configuration
public class RegisteredClientConfig {


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
    }

    /*
       in production use JDBC instead of in-memory client

    */

  /*  @Bean
    RegisteredClientRepository registeredClientRepository(DataSource dataSource) {
        return new JdbcRegisteredClientRepository(dataSource);
    }*/
}
