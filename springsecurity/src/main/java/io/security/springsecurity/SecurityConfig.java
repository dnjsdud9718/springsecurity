package io.security.springsecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * 사용자 정의 보안 설정
 *
 * @EnableWebSecurity를 클래스에 정의 모든 설정 코드는 람다 형식으로 작성(스프링 시큐리티 7 버전부터는 람다 형식만 지워할 예정 -> 컴파일 에러)
 * SecurityFilterChain을 빈으로 정의(사용자 정의)하게 되면 자동설정에 의한 SecurityFilterChain 빈은 생성되지 않는다.
 * SpringBootWebSecurityConfiguration -> defaultSecurityFilterChain bean 생성 안된다 조건 불만족 ->
 * @ConditionalOnMissingBean({SecurityFilterChain.class})
 */
@EnableWebSecurity
@Configuration
public class SecurityConfig {


    //    formLogin() API : FormLoginConfigurer 설정 클래스를 통해 여러 API를 설정. 내부적으로 UsernamePasswordAuthenticationFilter가 생성 폼방식의 인증 처리 담당.
//    @Bean(name = "securityFilterChain")
    public SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//           form login 방식(Customizer.withDefault: 자동설정, 시큐리티가 제공)
            .formLogin(form -> form
                    .loginPage(
                        "/loginPage")                               // 사용자 정의 로그인 페이지로 전환, 기본 로그인 페이지 무시
                    .loginProcessingUrl(
                        "/loginProc")                      // 사용자 이름과 비밀번호를 검증할 URL 지정(Form action)
                    .defaultSuccessUrl("/",
                        true) // 로그인 성공 이후 이동 페이지, alwaysUse가 true이면 무조건 지정된 페이지로 이동(deafult false)
                    // 인증 전에 보안이 필요한 페이지를 방문하다가 인증에 성공한 경우이면 이전 위치로 리다이렉트(false/true 모두)
                    .failureUrl(
                        "/failed")              // 인증에 실패할 경우 사용자에게 보내질 URL 지정, 기본값은 /login?error
                    .usernameParameter(
                        "userId")                           // 인증을 수행할 때 사용자 이름(ID)를 찾기 위해 확인하는 HTTP 매개변수 설정, 기본값은 username, front -> form input name
                    .passwordParameter(
                        "passwd")                           // 인증을 수행할 때 비밀번호를 찾기 위해 확인하는 HTTP 매개변수 설정, 기본값은 password, front -> form input name
                    // 인증 성공 시 사용할 AuthenticationSuccessHandler를 지정, 기본값은 SavedRequestAwareAuthenticationSuccessHandler이다.
                    .successHandler(new AuthenticationSuccessHandler() { // defaultSuccessUrl보다 우선순위 높다
                        @Override
                        public void onAuthenticationSuccess(HttpServletRequest request,
                            HttpServletResponse response, Authentication authentication)
                            throws IOException, ServletException {
                            System.out.println("authentication = " + authentication);
                            response.sendRedirect("/home");
                        }
                    })
                    // 인증 실패 시 사용할 AuthenticationFailureHandler 지정. 기본값은 SimpleUrlAuthenticationFailureHandler를 사용하여 /login?error로 리다이렉션
                    .failureHandler(new AuthenticationFailureHandler() { // failureUrl보다 우선순위 높다.
                        @Override
                        public void onAuthenticationFailure(HttpServletRequest request,
                            HttpServletResponse response, AuthenticationException exception)
                            throws IOException, ServletException {
                            System.out.println("exception.getMessage() = " + exception.getMessage());
                            response.sendRedirect("/login");
                        }
                    })
                    .permitAll()
                // failureUrl(), loginPage(), loginProcessingUrl()에 대한 URL에 모든 사용자 접근 허용 함
            );
        return http.build();
    }

    /**
     * rememberMe - 기억하기 인증 로그인할 때 자동으로 인증 정보를 기억하는 기능이다. UsernamePasswordAuthenticationFilter와 함께
     * 사용되며, AbstractAuthenticationProcessingFilter 슈퍼 클래스에서 훅을 통해 구현
     * <p>
     * 토큰 생성 기본적으로 암호화된 토큰으로 생성되어지며 브라우저에 쿠키를 보내고, 향후 세션에서 이를 감지하여 자동 로그인이 이뤄지는 방식
     * <p>
     * RememberService 구현체 TokenBasedRememberServices - 쿠키 기반 토큰의 보안을 위해 해싱 사용 (여기 중심으로 공부하자)
     * PersistentTokenBasedRememberService - 생성된 토큰을 저장하기 위해 DB나 영구 매체 사용
     * <p>
     * RememberMeAuthenticationFilter : SecurityContextHolder에 Authentication이 포함되지 않는 경우 실행되는 필터 ->
     * authentication이 이미 sercuritycontext에 있다면, 인증을 이미 받았다는 뜻이다. 따라서 인증이 되지 않은 경우에만
     * rememberMeAuthenticationFilter를 실행하여 authentication을 추가하는 작업을 하면 된다. -> 세션이 만료되었거나 어플리케이션 종료로
     * 인해서 인증 상태가 소멸된 겨우 토큰 기반 인증을 사용해 유효성을 검사하고 토큰(remember-me)이 검증되면 자동 로그인 처리
     */
//    @Bean(name = "securityFilterChain")
    public SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests((requests) -> requests.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            .rememberMe(rememberMe -> rememberMe
                .alwaysRemember(
                    true)               // 기억하기(remember-me) 매개변수가 설정되지 않았을 때(check box가 no checked)에도 쿠키가 항상 생성되어야 하는지에 대한 여부( default false)
                .tokenValiditySeconds(3600)         // 토큰이 유효한 시간(초 단위) 설정
                .userDetailsService(
                    userDetailsService()) // UserDetails 를 조회하기 위해 사용되는 UserDetailsService를 지정
                .rememberMeParameter(
                    "remember") // 로그인 시 사용자를 기억하기 위해 사용되는 HTTP매개변수, default 'remember-me'(쉽게 말해 checkbox name)
                .rememberMeCookieName(
                    "remember") // 기억하기(remember-me) 인증을 위한 토큰을 저장하는 쿠키 이름, default 'remember-me'
                .key("security") // remember-me 인증을 위해 사용되는 토큰을 식별하는 키를 설정.
            );
        return http.build();
    }

    /**
     * anonymous() 스프링 시큐리티에서 '익명으로 인증된' 사용자와 인증되지 않은 사용자 간에 실제 개념적 차이는 없으며 단지 엑세스 제어 속성을 구성하는 더 편리한
     * 방법을 제공한다고 볼수 있다. SecurityContextHolder 가 항상 Authentication 객체를 포함하고 null을 포함하지 않는다는 것을 규칙을
     * 세우게 되면 더 견고하게 작성 가능 인증 사용자와 익명 인증 사용자를 구분해서 어떤 기능을 수행하고자 할 때 유용할 수 있으며 익명 인증 객체를 세션에 저장하지
     * 않는다. 익명 인증 사용자의 권한을 별도로 운용할 수 있다. 즉 인증 된 사용자가 접근할 수 없도록 구성이 가능하다.
     * <p>
     * 인증 받은 사용자와 인증 받지 못한 사용자를 객체로 구분해서 사용하겠다. securityContextHolder -> securityContext 가지고 있다. 인증
     * 받은 사용자 -> securitycontext에 authentication 객체 저장 -> 인증 상태 유지, 인증 받은 사용자는 다시 session에 저장 익명 사용자
     * -> securitycontext에 authentication 객체 저장 -> but, session에 저장하지 않는다.
     * <p>
     * AnonymousAuthenticationFilter -> 현재 접속한 사용자가 인증 받지 못했으면 익명 사용자의 인증 객체 생성하고 securitycontext 에
     * 저장.
     * <p>
     * 스프링 MVC에서 익명 인증 사용하기 -> HttpServletRequest#getPrincipal을 사용하여 파라미터를 해결하는데 요청이 익명일 때 이 값은
     * null이다. -> 익명 사용자의 정보를 얻고 싶다면 아래처럼 해야 한다. -> 익명 요청에서 Authentication을 얻고 싶으면
     * @CurrentSecurityContext를 사용 -> CurrentSecurityContextArgumentResolver에서 요청을 가로채어 처리한다.
     * <p>
     * default anonymouse() 사용해도 된다. 굳이 변경할 사항이 없다.
     */
//    @Bean(name = "securityFilterChain")
    public SecurityFilterChain securityFilterChain3(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/anonymous").hasRole("GUEST") // GUEST 권한을 가진 사용자만 허용
                .requestMatchers("/anonymousContext", "/authentication")
                .permitAll() // 모든 사용자 허용 : 익명 사용자 참조하는 방법 실습하기 위해
                .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            .anonymous(anonymous -> anonymous
                .principal("guest")
                .authorities("ROLE_GUEST")
            );
        return http.build();
    }

    /**
     * 로그아웃 스프링 시큐리티는 formLogin()을 설정하면 자동으로 로그인페이지, 로그아웃 페이지 생성 DefaultLoginPageGeneratingFilter 가
     * 로그인 페이지 생성 DefaultLogoutGeneratingFilter 가 로그아웃페이지 생성 로그아웃 실행은 기본적으로 POST, /logout 으로만 가능하나
     * CSRF 기능을 비활성화할 경우 혹은 RequestMatcher를 사용할 경우 GET, PUT, DELTE도 가능 로그아웃 필터를 거치지 않고 스프링 MVC 에서
     * 커스텀 하게 구현할 수 있으며 로그인 페이지가 커스텀하게 생성될 경우 로그아웃 기능도 커스텀하게 구현해야 한다.
     * <p>
     * CSRF : 어떤 공격자가 사용자 세션을 가지고 다른 목적에 사용하는 것을 방지하는 기능(추후에 공부할 예정)
     */
//    @Bean(name = "securityFilterChain")
    public SecurityFilterChain securityFilterChain4(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/logoutSuccess").permitAll()
                .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable) // CSRF 비활성화 -> POST, GET, PUT, DELETE 로 logout 가능
            .logout(logout -> logout
                .logoutUrl("/logout") // 로그아웃이 발생하는 URL 지정(default: /logout)
                // 로그아웃이 발생하는 RequestMatcher 을 지정한다. logoutUrl()보다 우선순위 높음
                // 메서드를 지정하지 ㅇ낳으면 logout URL이 어떤 메서드로든 요청될 때 로그아웃 가능
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "POST"))
                .logoutSuccessUrl("/logoutSuccess") // 로그아웃이 발생한 후 리다이렉션 될 URL(default: /login?logout
                // 사용할 LogoutSuccessHandler 설정 -> logoutSuccessUrl() 무시
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request,
                        HttpServletResponse response, Authentication authentication)
                        throws IOException, ServletException {
                        System.out.println("logoutSuccessHandler");
                        response.sendRedirect("/logoutSuccess");
                    }
                })
                .deleteCookies("JSESSIONID", "remember-me") // 로그아웃 성공 시 제거될 쿠키 이름을 지정
                .invalidateHttpSession(true) // HttpSession을 무효화해야 하는 경우 true(default: true)
                .clearAuthentication(true) // 로그아웃 시 SecurityContextLogoutHaandler 가 authentication을 삭제 여부 명시
                .addLogoutHandler(new LogoutHandler() { // 기존의 로그아웃 핸들러 뒤에 새로운 LogoutHandler 추가
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response,
                        Authentication authentication) {
                        HttpSession session = request.getSession(false);
                        if(session != null) session.invalidate();
                        SecurityContextHolder.getContextHolderStrategy().getContext()
                            .setAuthentication(null);
                        SecurityContextHolder.getContextHolderStrategy().clearContext();
                    }
                })
                .permitAll() // logoutUrl(), RequestMathcher()의 URL에 대한 모든 사용자 접근 허용
            );
        return http.build();
    }

    /**
     * RequestCache & SavedRequest
     * 특별한 설정하지 않아도 자동 처리된다. -> 내부 처리 커스텀 필요 시 수정하면 된다.
     */
    @Bean(name = "securityFilterChain")
    public SecurityFilterChain securityFilterChain5(HttpSecurity http) throws Exception {
        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setMatchingRequestParameterName("customParam=y");
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/logoutSuccess").permitAll()
                .anyRequest().authenticated())
            .formLogin(form -> form
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request,
                        HttpServletResponse response, Authentication authentication)
                        throws IOException, ServletException {
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        response.sendRedirect(redirectUrl);
                    }
                }))
            .requestCache(cache -> cache.requestCache((requestCache)));
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
