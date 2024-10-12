package com.americanworx.auth.config;


import com.americanworx.auth.config.jwt.JwtTokenValidator;
import com.americanworx.auth.utils.AuthEntryPointJwt;
//import com.nimbusds.jose.jwk.JWKSet;
//import com.nimbusds.jose.jwk.RSAKey;
//import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
//import com.nimbusds.jose.jwk.source.JWKSource;
//import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
//import org.springframework.core.annotation.Order;
//
//import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
//import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.oauth2.core.AuthorizationGrantType;
//import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
//import org.springframework.security.oauth2.core.oidc.OidcScopes;
//import org.springframework.security.oauth2.jwt.JwtDecoder;
//import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
//import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
//import java.security.interfaces.RSAPrivateKey;
//import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.List;
//import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired private UserDetailsService userDetailsService;

//    @Bean
//    @Order(1)
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//                .oidc(Customizer.withDefaults());
//        http.exceptionHandling((exception) -> exception.defaultAuthenticationEntryPointFor(
//                new LoginUrlAuthenticationEntryPoint("/login"),
//                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
//        ))
//                .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));
//        return http.build();
//    }

    @Bean
//    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.logout(lOut -> {
            lOut.logoutSuccessHandler((new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK)));
        });
        http.sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .cors(AbstractHttpConfigurer::disable)
                .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
                .authorizeHttpRequests((authorizeRequests) -> authorizeRequests
                .requestMatchers("/login", "/saveUser" ).permitAll()
                .anyRequest().authenticated()
        ).addFilterBefore(new JwtTokenValidator(), BasicAuthenticationFilter.class);;

        return http.build();
    }

//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("shopping")
//                .clientSecret("{noop}donkey")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .redirectUri("http://192.168.1.75:8040/login/oauth2/code/shopping")
//                .postLogoutRedirectUri("http://192.168.1.75:8040/")
//                .scope(OidcScopes.OPENID)
//                .scope(OidcScopes.PROFILE)
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//                .build();
//        return new InMemoryRegisteredClientRepository(registeredClient);
//    }

//    @Bean
//    public JWKSource<SecurityContext> jwkSource() {
//        KeyPair keyPair = generateRsaKey();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//        RSAKey rsaKey = new RSAKey.Builder(publicKey)
//                .privateKey(privateKey)
//                .keyID(UUID.randomUUID().toString())
//                .build();
//        JWKSet jwkSet = new JWKSet(rsaKey);
//        return new ImmutableJWKSet<>(jwkSet);
//    }

//    @Bean
//    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
//        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
//    }
//
//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder().build();
//    }
    private CorsConfigurationSource corsConfigurationSource() {
        return new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration ccfg = new CorsConfiguration();
                ccfg.setAllowedOrigins(List.of("http://192.168.1.76:8090/"));
                ccfg.setAllowedMethods(Collections.singletonList("*"));
                ccfg.setAllowCredentials(true);
                ccfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PUT","OPTIONS","PATCH", "DELETE"));
                ccfg.setAllowedHeaders(Collections.singletonList("*"));
                ccfg.setExposedHeaders(List.of("Authorization"));
                ccfg.setMaxAge(7200L);
                return ccfg;
            }
        };

    }

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(authProvider);
    }

    private KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
}
