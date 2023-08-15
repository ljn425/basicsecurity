package io.security.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfigV1 {
    private final UserDetailsService userDetailsService;

    public SecurityConfigV1(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                // 인가 정책
                .authorizeHttpRequests((authorizeRequests) ->
                        authorizeRequests // 요청에 대한 보안 검사 시작
                                .anyRequest() // 어떠한 url 요청에도 적용
                                .authenticated() // 인증된 사용자만 접근 가능
                )
                // 인증 정책(form 로그인 인증 방식)
                .formLogin(formLogin ->
                        formLogin
//                                .loginPage("/loginPage") // 로그인 페이지 경로 custom 가능
//                                .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
//                                .failureUrl("/login") // 로그인 실패 후 이동 페이지
//                                .usernameParameter("userId") // 아이디 파라미터명 설정
//                                .passwordParameter("passwd") // 패스워드 파라미터명 설정
//                                .loginProcessingUrl("/login_proc") // 로그인 Form Action Url
//                                .successHandler((request, response, authentication) -> { // 로그인 성공 후 핸들러
//                                    System.out.println("authentication : " + authentication.getName());
//                                    response.sendRedirect("/");
//                                })
//                                .failureHandler((request, response, exception) -> { // 로그인 실패 후 핸들러
//                                    System.out.println("exception : " + exception.getMessage());
//                                    response.sendRedirect("/login");
//                                })
                                .permitAll() // 로그인 페이지는 누구나 접근 가능
                )
//                .logout(logout ->
//                        logout
//                                .logoutUrl("/logout") // 로그아웃 처리 URL
//                                .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동 페이지
//                                .deleteCookies("remember-me") // 로그아웃 후 쿠키 삭제
//                                .addLogoutHandler((request, response, authentication) -> { // 로그아웃 핸들러
//                                    HttpSession session = request.getSession();
//                                    session.invalidate();   // 세션 무효화
//                                })
//                                .logoutSuccessHandler((request, response, authentication) -> { // 로그아웃 성공 후 핸들러
//                                    response.sendRedirect("/login");
//                                })
//                )
                .rememberMe(rememberMe ->
                        rememberMe
                                .rememberMeParameter("remember") // 로그인 폼의 rememberMe html name 설정
                                .tokenValiditySeconds(3600) // Default 14일
                                .alwaysRemember(false) // 리멤버 미 기능이 활성화되지 않아도 항상 실행(true), 기본값은 false
                                .userDetailsService(userDetailsService) // 리멤버 미 기능 동작 시 필요한 정보를 가져오는 곳
                        )
                .build();
    }
}
