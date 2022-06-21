package com.java.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@EnableWebFluxSecurity
public class SecurityWebfluxConfig {

    @Bean
    SecurityWebFilterChain webFluxSecurityFilterChain(ServerHttpSecurity http) throws Exception {
        http.securityContextRepository(new NoOpServerSecurityContextAutoRepository(tokenProvider))
                .httpBasic().disable()
                .formLogin().disable()
                .csrf().disable()
                .logout().disable();
        http.addFilterAt(corsFilter(), SecurityWebFiltersOrder.CORS)
                .authorizeExchange()
                .matchers(EndpointRequest.to("health", "info"))
                .permitAll()
                .and()
                .authorizeExchange()
                .pathMatchers(HttpMethod.OPTIONS)
                .permitAll()
                .and()
                .authorizeExchange()
                .pathMatchers(HttpMethod.PUT)
                .denyAll()
                .and()
                .authorizeExchange()
                .pathMatchers(HttpMethod.DELETE)
                .denyAll()
                .and()
                .authorizeExchange()
                .pathMatchers(HttpMethod.HEAD)
                .denyAll()
                .and()
                .authorizeExchange()
                .pathMatchers(HttpMethod.PATCH)
                .denyAll()
                .and()
                .authorizeExchange()
                .pathMatchers(HttpMethod.TRACE)
                .denyAll()
                .and()
                .authorizeExchange()
                .pathMatchers(excludedAuthPages).permitAll()
                .and()
                .authorizeExchange()
                .pathMatchers(authenticatedPages).authenticated()
                .and()
                .exceptionHandling()
                .accessDeniedHandler(new AccessDeniedEntryPointd())
                .and()
                .authorizeExchange()
                .and()
                .addFilterAt(webFilter(), SecurityWebFiltersOrder.AUTHORIZATION)
                .authorizeExchange()
                .pathMatchers("/**").access(new JwtAuthorizationManager(tokenProvider))
                .anyExchange().authenticated();
        return http.build();
    }
}
