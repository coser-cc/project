package com.java.gateway.config;

import com.java.gateway.filter.AuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@EnableWebFluxSecurity
public class SecurityWebfluxConfig {

    //security的鉴权排除的url列表
    public static final String[] excludedAuthPages = {"/health", "/auth/**"};

    @Bean
    SecurityWebFilterChain webFluxSecurityFilterChain(ServerHttpSecurity http) {
        http
                // 禁用 CSRF
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                // 配置 CORS 策略
                .cors(ServerHttpSecurity.CorsSpec::disable)
                // WebFlux 应用程序中的安全上下文存储在 ServerSecurityContextRepository 中，配置 NoOpServerSecurityContextRepository 会使我们的应用程序无状态
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                // excludedAuthPages中的路径全部通行
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.pathMatchers(excludedAuthPages).permitAll())
                // 其他路径权限验证
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.anyExchange().authenticated())
                .addFilterAt(new AuthFilter(), SecurityWebFiltersOrder.AUTHENTICATION);
        return http.build();
    }

}
