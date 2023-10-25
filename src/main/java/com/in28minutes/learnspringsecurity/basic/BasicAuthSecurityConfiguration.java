package com.in28minutes.learnspringsecurity.basic;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

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

  // 1. CORS 전역 설정을 하려면 addCorsMapping 방식 사용
  // 2. 다른 방법 : 특정 요청 메서드, 컨트롤러에 @CrossOrigin 추가 -> 커스터마이징할 수 있음
  // ex) @CrossOrigin(origins="http://www.in28minutes.com")으로 보내는 경우
  @Bean
  public WebMvcConfigurer corsConfigurer() {
    return new WebMvcConfigurer() {
      @Override
      public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // 모든 URL에 대한 요청을 허용
            .allowedMethods("*") // GET, POST, PUT, PATCH, DELETE 등등 method 허용
            .allowedOrigins("http://localhost:3000"); // localhost:3030에서 오는 요청 허용
      }
    };
  }
  
  // UserDetailsService 를 설정
  // 사용자 세부 정보를 가져올 때 이 인터페이스를 사용하게 됨
  // Core interface which loads user-specific data.
  // InMemoryUserDetailsManager 는 UserDetailsManager 의 비지속적 구현 (휘발성이라고 생각하면 될듯)
  @Bean
  public UserDetailsService userDetailsService() { // 메모리에 유저 정보를 넣어줌 (휘발성) -> 운영에서는 권장X

    var user = User.withUsername("in28minutes") // User 객체를 생성하는 방법
        .password("{noop}dummy")
        .roles(Role.USER.name()) // Enum 으로 넣어주자
        .build();

    var admin = User.withUsername("admin")
        .password("{noop}dummy")
        .roles(Role.ADMIN.name())
        .build();

    return new InMemoryUserDetailsManager(user, admin);
  }
}

