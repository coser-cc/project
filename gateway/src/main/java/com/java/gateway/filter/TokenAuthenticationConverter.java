package com.java.gateway.filter;

import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class TokenAuthenticationConverter implements ServerAuthenticationConverter {
    /**
     * Converts a {@link ServerWebExchange} to an {@link Authentication}
     *
     * @param exchange The {@link ServerWebExchange}
     * @return A {@link Mono} representing an {@link Authentication}
     */
    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        String authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        return Mono.just(new UsernamePasswordAuthenticationToken(authorization, "password"));
    }
}
