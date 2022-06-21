package com.java.gateway.config;

import com.java.gateway.filter.NoOpServerSecurityContextAutoRepository;
import org.springframework.boot.actuate.autoconfigure.security.reactive.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

@EnableWebFluxSecurity
public class SecurityWebfluxConfig {

    @Bean
    SecurityWebFilterChain webFluxSecurityFilterChain(ServerHttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .cors().disable()
                .httpBasic().disable()
                .formLogin().disable()
                .logout().disable();
        http
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.matchers(EndpointRequest.to("health", "info")).permitAll())
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.pathMatchers(HttpMethod.OPTIONS).permitAll())
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.pathMatchers(HttpMethod.PUT).denyAll())
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.pathMatchers(HttpMethod.DELETE).denyAll())
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.pathMatchers(HttpMethod.HEAD).denyAll())
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.pathMatchers(HttpMethod.PATCH).denyAll())
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.pathMatchers(HttpMethod.TRACE).denyAll())
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.pathMatchers(excludedAuthPages).permitAll())
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.pathMatchers(authenticatedPages).authenticated())
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.pathMatchers("/**").access(new JwtAuthorizationManager(tokenProvider)))
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.anyExchange().authenticated());
        http
                .securityContextRepository(new NoOpServerSecurityContextAutoRepository(tokenProvider))
                .exceptionHandling().accessDeniedHandler(new AccessDeniedEntryPointd())
                .addFilterAt(webFilter(), SecurityWebFiltersOrder.AUTHORIZATION);
        return http.build();
    }

    public AuthenticationWebFilter webFilter() {
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(new JWTReactiveAuthenticationManager(userCache, tokenProvider, coreUserApi));
        authenticationWebFilter.setServerAuthenticationConverter(new TokenAuthenticationConverter(guestList, tokenProvider));
        authenticationWebFilter.setRequiresAuthenticationMatcher(new NegatedServerWebExchangeMatcher(ServerWebExchangeMatchers.pathMatchers(excludedAuthPages)));
        authenticationWebFilter.setSecurityContextRepository(new NoOpServerSecurityContextAutoRepository(tokenProvider));
        return authenticationWebFilter;
    }
}
