package com.in28minutes.learnspringsecurity.basic;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class BasicAuthSecurityConfiguration {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> {
      auth.anyRequest().authenticated(); // 모든 요청을 인증하도록 정의
    });
    // http.formLogin(); -> form 로그인 방식을 사용하지 않음
    http.sessionManagement(
      session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않음
    );
    http.httpBasic();
    http.csrf().disable();
    return http.build();
  }
}
