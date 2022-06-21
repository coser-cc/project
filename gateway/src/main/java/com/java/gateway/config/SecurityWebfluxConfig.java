package com.java.gateway.config;

import com.java.gateway.filter.NoOpServerSecurityContextAutoRepository;
import org.springframework.boot.actuate.autoconfigure.security.reactive.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
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
                .authorizeExchange().matchers(EndpointRequest.to("health", "info")).permitAll()
                .and()
                .authorizeExchange().pathMatchers(HttpMethod.OPTIONS).permitAll()
                .and()
                .authorizeExchange().pathMatchers(HttpMethod.PUT).denyAll()
                .and()
                .authorizeExchange().pathMatchers(HttpMethod.DELETE).denyAll()
                .and()
                .authorizeExchange().pathMatchers(HttpMethod.HEAD).denyAll()
                .and()
                .authorizeExchange().pathMatchers(HttpMethod.PATCH).denyAll()
                .and()
                .authorizeExchange().pathMatchers(HttpMethod.TRACE).denyAll()
                .and()
                .authorizeExchange().pathMatchers(excludedAuthPages).permitAll()
                .and()
                .authorizeExchange().pathMatchers(authenticatedPages).authenticated()
                .and()
                .authorizeExchange().pathMatchers("/**").access(new JwtAuthorizationManager(tokenProvider))
                .and()
                .anyExchange().authenticated();
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
