package com.java.gateway.filter;

import com.alibaba.fastjson2.JSONObject;
import com.java.gateway.provider.TokenProvider;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

public class JwtAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

    private final TokenProvider tokenProvider;

    public JwtAuthorizationManager(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    /**
     * Determines if access is granted for a specific authentication and object.
     *
     * @param authentication the Authentication to check
     * @param context        the object to check
     * @return an decision or empty Mono if no decision could be made.
     */
    @Override
    public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, AuthorizationContext context) {
        return authentication.map(g -> {
            JSONObject pathList = (JSONObject) g.getDetails();
//            JSONObject userJson = tokenProvider.getLoginUserInfo(g.getName());
            JSONObject userJson = pathList.getJSONObject("aaa");
            if (userJson.containsKey("isAdmin")) {
                return new AuthorizationDecision(true);
            } else {
                if (!pathList.isEmpty() && pathList.getJSONArray("pathList").stream().anyMatch(o -> (context.getExchange().getRequest().getPath().toString().contains(o.toString())))) {
                    return new AuthorizationDecision(true);
                } else {
                    return new AuthorizationDecision(false);
                }
            }
        });
    }
}
