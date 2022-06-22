package com.java.gateway.config;

import com.alibaba.fastjson2.JSONObject;
import com.java.gateway.provider.TokenProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Collections;

public class JWTReactiveAuthenticationManager implements ReactiveAuthenticationManager {

    /**
     * Attempts to authenticate the provided {@link Authentication}
     *
     * @param authentication the {@link Authentication} to test
     * @return if authentication is successful an {@link Authentication} is returned. If
     * authentication cannot be determined, an empty Mono is returned. If authentication
     * fails, a Mono error is returned.
     */
    @Override
    public Mono<Authentication> authenticate(final Authentication authentication) {
        if (authentication.isAuthenticated()) {
            return Mono.just(authentication);
        }
        return Mono.just(authentication)
                .switchIfEmpty(Mono.defer(this::raiseBadCredentials))
                .cast(UsernamePasswordAuthenticationToken.class)
                .flatMap(this::authenticateToken)
                .publishOn(Schedulers.parallel())
                .onErrorResume(e -> raiseBadCredentials())
                .switchIfEmpty(Mono.defer(this::raiseBadCredentials))
                .map(u -> {
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getName(), Collections.EMPTY_LIST);
                    usernamePasswordAuthenticationToken.setDetails(u);
                    return usernamePasswordAuthenticationToken;
                });
    }

    private <T> Mono<T> raiseBadCredentials() {
        return Mono.error(new BadCredentialsException("Invalid Credentials"));
    }

    private Mono<JSONObject> authenticateToken(final UsernamePasswordAuthenticationToken authenticationToken) {
//        String username = tokenProvider.getLoginUserMobile(authenticationToken.getName());
        String username = "username";
        if (username != null) {
            return Mono.just(JSONObject.of("username", username));
        }
        return null;
    }
}
