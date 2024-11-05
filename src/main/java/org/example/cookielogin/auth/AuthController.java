package org.example.cookielogin.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.example.cookielogin.member.MemberRole;
import org.example.cookielogin.security.JwtTokenProvider;
import org.example.cookielogin.security.SecurityUserDetailService;
import org.example.cookielogin.security.dto.TokenInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Log4j2
@RequiredArgsConstructor
@RestController
@CrossOrigin(origins = "*")
public class AuthController {

    private final AuthService authService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private SecurityUserDetailService userDetailService;

    @PostMapping("/login")
    public Map login(@RequestBody Map<String, String> user, HttpServletResponse response){
        log.info(user.get("email"));
        log.info(user.get("password"));
        return authService.login(user, response);
    }

//    @GetMapping("/login/oauth2/code/kakao")
//    public ResponseEntity<?> oauth2Login(OAuth2AuthenticationToken authentication, HttpServletResponse response) {
//        log.info("OAuth2AuthenticationToken: " + authentication);
//        // OAuth2 인증 정보로 사용자 로그인 처리
//        return authService.handleOAuth2Login(authentication, response);
//    }

    @GetMapping("/login/oauth2/kakao")
    public ResponseEntity<?> oauth2Login(OAuth2AuthenticationToken authentication, HttpServletResponse response) {

//        log.info("OAuth2AuthenticationToken: " + authentication);
        // OAuth2 인증 정보로 사용자 로그인 처리
        return authService.handleOAuth2Login(authentication, response);
    }

    @PostMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response){
        log.info("로그아웃 실행?");
        // 현재 인증 정보를 지우고 세션을 무효화
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if(auth != null){
            new SecurityContextLogoutHandler().logout(request, response, auth);

            // 프론트 쪽에 가지고 있는 accessToken 이때 따로 삭제해주어야 할 듯
            
            // 쿠키 삭제
//            Cookie accessToken = new Cookie("accessToken", null); // 삭제할 쿠키 이름
//            accessToken.setPath("/"); // 쿠키의 경로를 설정 (모든 경로에서 삭제)
//            accessToken.setMaxAge(0); // 쿠키의 유효 기간을 0으로 설정하여 삭제
//            response.addCookie(accessToken); // 응답에 쿠키 추가

            Cookie refreshToken = new Cookie("refreshToken", null); // 삭제할 쿠키 이름
            refreshToken.setPath("/"); // 쿠키의 경로를 설정 (모든 경로에서 삭제)
            refreshToken.setMaxAge(0); // 쿠키의 유효 기간을 0으로 설정하여 삭제
            response.addCookie(refreshToken); // 응답에 쿠키 추가

            response.setHeader("authorization", "");
        }

        return "로그아웃 완료!";
    }

    @GetMapping("/test")
    public String test(HttpServletResponse response){
        if(response.getHeader("authorization") != null){
            return response.getHeader("authorization").substring(7);
        }
        return response.getHeader("authorization");
    }

}
