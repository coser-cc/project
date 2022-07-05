package com.java.gateway.config;

import com.java.gateway.filter.TokenAuthenticationConverter;
import org.springframework.boot.actuate.autoconfigure.security.reactive.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.util.pattern.PathPatternParser;

@EnableWebFluxSecurity
public class SecurityWebfluxConfig {

    //security的鉴权排除的url列表
    public static final String[] excludedAuthPages = {"/health"};

    @Bean
    SecurityWebFilterChain webFluxSecurityFilterChain(ServerHttpSecurity http) {
        http
                // 禁用 CSRF
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                // 配置 CORS 策略
                .cors(corsSpec -> corsSpec.configurationSource(exchange -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.addAllowedOrigin("*");
                    // 允许提交的请求头，*表示全部允许
                    config.addAllowedHeader("*");
                    // 允许提交的请求方法，*表示全部允许
                    config.addAllowedMethod("*");
                    // 允许cookies跨域
                    config.setAllowCredentials(true);
                    // 预检请求的缓存时间（秒），即在这个时间段里，对于相同的跨域请求不会再预检了
                    config.setMaxAge(18000L);
                    return config;
                }))
                /*
                  WebFlux 应用程序中的安全上下文存储在 ServerSecurityContextRepository 中。
                  它的 WebSessionServerSecurityContextRepository 实现（默认使用）将上下文存储在会话中。
                  相反，配置 NoOpServerSecurityContextRepository 会使我们的应用程序无状态
                 */
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.matchers(EndpointRequest.to("health", "info")).permitAll())
                // excludedAuthPages 中的路径全部通行
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.pathMatchers(excludedAuthPages).permitAll())
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.anyExchange().authenticated())
                // 配置权限验证Filter
                .addFilterAt(webFilter(), SecurityWebFiltersOrder.AUTHORIZATION);
        return http.build();
    }

    @Bean
    public CorsWebFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOrigin("*");
        // 允许提交的请求头，*表示全部允许
        config.addAllowedHeader("*");
        // 允许提交的请求方法，*表示全部允许
        config.addAllowedMethod("*");
        config.setAllowCredentials(true); // 允许cookies跨域
        // 预检请求的缓存时间（秒），即在这个时间段里，对于相同的跨域请求不会再预检了
        config.setMaxAge(18000L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource(new PathPatternParser());
        source.registerCorsConfiguration("/**", config);
        return new CorsWebFilter(source);
    }

    public AuthenticationWebFilter webFilter() {
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(new JWTReactiveAuthenticationManager());
        authenticationWebFilter.setServerAuthenticationConverter(new TokenAuthenticationConverter());
        authenticationWebFilter.setRequiresAuthenticationMatcher(new NegatedServerWebExchangeMatcher(ServerWebExchangeMatchers.pathMatchers(excludedAuthPages)));
        return authenticationWebFilter;
    }
}
