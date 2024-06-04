package io.security.springsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * 사용자 정의 보안 설정
 * @EnableWebSecurity를 클래스에 정의
 * 모든 설정 코드는 람다 형식으로 작성(스프링 시큐리티 7 버전부터는 람다 형식만 지워할 예정 -> 컴파일 에러)
 * SecurityFilterChain을 빈으로 정의(사용자 정의)하게 되면 자동설정에 의한 SecurityFilterChain 빈은 생성되지 않는다.
 * SpringBootWebSecurityConfiguration -> defaultSecurityFilterChain bean 생성 안된다
 * 조건 불만족 -> @ConditionalOnMissingBean({SecurityFilterChain.class})
 */
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults());
        return http.build();
    }

    // 사용자 추가 -> 자바 설정 클래스에서 등록(application.yml가 중복이 있을 경우 우선권 가진다.)
    // 여러명 추가 가능
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
            .password("{noop}2222")
            .roles("USER")
            .build();
        return new InMemoryUserDetailsManager(user);
    }
}
