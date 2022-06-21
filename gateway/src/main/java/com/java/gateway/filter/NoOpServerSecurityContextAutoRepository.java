package com.java.gateway.filter;

import org.apache.commons.lang.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collections;

@Component
public class NoOpServerSecurityContextAutoRepository implements ServerSecurityContextRepository {
    private TokenProvider tokenProvider;

    public NoOpServerSecurityContextAutoRepository(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        return Mono.empty();

    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        String token = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (StringUtils.isNotBlank(token)) {
            SecurityContext securityContext = new SecurityContextImpl();
            securityContext.setAuthentication(new UsernamePasswordAuthenticationToken("password", token, Collections.EMPTY_LIST));
            return Mono.justOrEmpty(securityContext);
        } else {
            return Mono.empty();
        }
    }
}
