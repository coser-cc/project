package com.java.gateway.filter;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

public class AuthenticationWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return this.requiresAuthenticationMatcher.matches(exchange)
                .filter( matchResult -> matchResult.isMatch())
                .flatMap( matchResult -> this.authenticationConverter.convert(exchange))
                .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
                .flatMap( token -> authenticate(exchange, chain, token))
                .onErrorResume(AuthenticationException.class, e -> this.authenticationFailureHandler
                        .onAuthenticationFailure(new WebFilterExchange(exchange, chain), e));
    }

    private Mono<Void> authenticate(ServerWebExchange exchange, WebFilterChain chain, Authentication token) {
        return this.authenticationManagerResolver.resolve(exchange)
                .flatMap(authenticationManager -> authenticationManager.authenticate(token))
                .switchIfEmpty(Mono.defer(() -> Mono.error(new IllegalStateException("No provider found for " + token.getClass()))))
                .flatMap(authentication -> onAuthenticationSuccess(authentication, new WebFilterExchange(exchange, chain)));
    }

    protected Mono<Void> onAuthenticationSuccess(Authentication authentication, WebFilterExchange webFilterExchange) {
        ServerWebExchange exchange = webFilterExchange.getExchange();
        SecurityContextImpl securityContext = new SecurityContextImpl();
        securityContext.setAuthentication(authentication);
        return this.securityContextRepository.save(exchange, securityContext)
                .then(this.authenticationSuccessHandler
                        .onAuthenticationSuccess(webFilterExchange, authentication))
                .subscriberContext(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)));
    }

}
