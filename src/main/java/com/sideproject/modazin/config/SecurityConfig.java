package com.sideproject.modazin.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.Arrays;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
// test 주석
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/").permitAll()
                            .requestMatchers("/user/login").permitAll()
                            .requestMatchers("/user/signup").permitAll()
                            .anyRequest().authenticated();
                })
                .formLogin(form -> {
                    form.loginProcessingUrl("/login")
                            .loginPage("/user/login") // 로그인 페이지
                            .permitAll()
                            .failureUrl("/user/login") // 로그인 실패 시 이동 할 페이지
                            .defaultSuccessUrl("/"); // 로그인 성공시 이동페이지
                })
                .logout((out) -> {
                            out.logoutSuccessUrl("/user/login") // 로그아웃성공 페이지
                                    .logoutUrl("/logout") //로그아웃성공 시 이동할 url
                                    .invalidateHttpSession(true) /*로그아웃시 세션 제거*/
                                    .deleteCookies("JSESSIONID") /*쿠키 제거*/
                                    .clearAuthentication(true) /*권한정보 제거*/
                                    .permitAll();
                        }
                );

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*")); // 모든 출처 허용
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS")); // 모든 HTTP 메서드 허용
        configuration.setAllowCredentials(true);
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
