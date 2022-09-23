package com.java.gateway.filter;

import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

public class AuthFilter implements WebFilter {

    /**
     * Process the Web request and (optionally) delegate to the next
     * {@code WebFilter} through the given {@link WebFilterChain}.
     *
     * @param exchange the current server exchange
     * @param chain    provides a way to delegate to the next filter
     * @return {@code Mono<Void>} to indicate when request processing is complete
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // 获取请求
        ServerHttpRequest request = exchange.getRequest();
        // 请求方式
        String method = request.getMethodValue();
        // 请求路径
        String url = request.getURI().getPath();
        // 请求头
        HttpHeaders headers = request.getHeaders();
        request.getHeaders().add("type", "");
        return chain.filter(exchange);
    }
}
