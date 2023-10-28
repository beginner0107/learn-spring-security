package com.in28minutes.learnspringsecurity.jwt;

import static org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION;

import com.in28minutes.learnspringsecurity.basic.Role;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class JwtSecurityConfiguration {

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
    http.headers().frameOptions().sameOrigin(); // 요청이 동일한 오리진에서 오는 경우 해당 애플리케이션에 대한 프레임을 허용하도록 지정
    http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

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

  @Bean
  public UserDetailsService userDetailsService(
      DataSource dataSource) { // DataSource를 주입해준다.

    var user = User.withUsername("in28minutes") // User 객체를 생성하는 방법
        .password("{noop}dummy")
        .roles(Role.USER.name()) // Enum 으로 넣어주자
        .build();

    var admin = User.withUsername("admin")
        .password("{noop}dummy")
        .roles(Role.ADMIN.name())
        .build();
    // InMemoryUserDetailsManager -> JdbcUserDetailsManager
    var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
    jdbcUserDetailsManager.createUser(user);
    jdbcUserDetailsManager.createUser(admin);
    return jdbcUserDetailsManager;
  }

  @Bean
  public DataSource dataSource () {
    return new EmbeddedDatabaseBuilder()
        .setType(EmbeddedDatabaseType.H2) // EmbeddedDatabaseType -> DERBY, H2, HSQL
        .addScript(DEFAULT_USER_SCHEMA_DDL_LOCATION) // JdbcDaoImpl 에 있는 ddl Script를 가지고 와서 사용할 예정
        .build();
  }

  // RSA키 만들기 Create Key Pair
  // use java.security.KeyPairGenerator
  // can use openssl as well
  @Bean
  public KeyPair keyPair() {
    try {
      var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      return keyPairGenerator.generateKeyPair();
    } catch (Exception ex) {
      throw new RuntimeException(ex);
    }
  }

  // Create RSA Key object using Key Pair
  @Bean
  public RSAKey rsaKey(KeyPair keyPair) {
    return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic()) // 공개키
        .privateKey(keyPair.getPrivate()) // 개인키
        .keyID(UUID.randomUUID().toString())
        .build();
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
    var jwkSet = new JWKSet(rsaKey);
    return (jwkSelector, context) -> jwkSelector.select(jwkSet);
  }

  @Bean
  public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
    return NimbusJwtDecoder
        .withPublicKey(rsaKey.toRSAPublicKey())
        .build();
  }

  @Bean
  public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
    return new NimbusJwtEncoder(jwkSource);
  }
}

