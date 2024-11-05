package org.example.cookielogin.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.example.cookielogin.member.Member;
import org.example.cookielogin.member.MemberRepository;
import org.example.cookielogin.member.MemberRole;
import org.example.cookielogin.security.JwtTokenProvider;
import org.example.cookielogin.security.SecurityUserDetailService;
import org.example.cookielogin.security.dto.TokenInfo;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Log4j2
@Service
@RequiredArgsConstructor
public class AuthService {

    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final SecurityUserDetailService userDetailService;
    private final PasswordEncoder passwordEncoder;

    public Map login(Map<String, String> user, HttpServletResponse response) {
        // 사용자 인증 정보 생성
        UserDetails userDetails = userDetailService.loadUserByUsername(user.get("email"));
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, user.get("password"),
                userDetails.getAuthorities());

        // 인증 정보를 SecurityContextHolder에 설정(저장)
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 인증이 완료된 후 DB에 저장되어 있는 회원의 이메일, 비밀번호 검사
        Optional<Member> optionalMember = memberRepository.findByEmail(user.get("email"));

        Member member = optionalMember.orElseThrow(() -> new IllegalArgumentException("가입되지 않은 이메일입니다."));
        if (!passwordEncoder.matches(user.get("password"), member.getPassword())) {
            throw new IllegalArgumentException("이메일 또는 비밀번호가 일치하지 않습니다.");
        }

        log.info("로그인한 사용자: {}", member.getEmail());
        log.info("사용자 권한: {}", userDetails.getAuthorities());

        // Jwt 토큰 생성(인가)
        TokenInfo jwtToken = jwtTokenProvider.generateToken(member.getEmail(), member.getName(), member.getMemberRoleList());

        Map result = new HashMap();

        result.put("email", member.getEmail());
        result.put("name", member.getName());
        result.put("roles", member.getMemberRoleList());
        result.put("accessToken", jwtToken.getAccessToken());

        // 쿠키 생성 및 설정
//        Cookie accessToken = new Cookie("accessToken", jwtToken.getAccessToken());
//        accessToken.setDomain("localhost");
//        accessToken.setPath("/");
//        accessToken.setMaxAge(60 * 10); // 10분
//        accessToken.setSecure(true);
//        accessToken.setHttpOnly(true);
//        response.addCookie(accessToken);

        Cookie refreshToken = new Cookie("refreshToken", jwtToken.getRefreshToken());
        refreshToken.setDomain("localhost");
        refreshToken.setPath("/");
        refreshToken.setMaxAge(60 * 60 * 24);   // 24시간
        refreshToken.setSecure(true);
        refreshToken.setHttpOnly(true);
        response.addCookie(refreshToken);

        response.setHeader("Set-Cookie", "");

        // 쿠키를 HttpServletResponse에 추가
//        response.addCookie(accessToken);
//        response.addCookie(refreshToken);

        // ResponseEntity를 사용하여 응답 반환
//        HttpHeaders headers = new HttpHeaders();
//        headers.add(HttpHeaders.SET_COOKIE, accessToken.toString());
//        headers.add(HttpHeaders.SET_COOKIE, refreshToken.toString());

        // 응답에 상태코드 반환(리액트에서는 상태코드를 확인하여 처리)
//        return ResponseEntity.ok()
//                .headers(headers)
//                .body("로그인 성공");
        return result;
    }

    public ResponseEntity<?> handleOAuth2Login(OAuth2AuthenticationToken authentication, HttpServletResponse response) {
        OAuth2User oAuth2User = authentication.getPrincipal();

        // 사용자 정보 추출
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        // 사용자 정보로 DB에 저장 또는 업데이트
        Optional<Member> optionalMember = memberRepository.findByEmail(email);
        Member member;

        if (optionalMember.isPresent()) {
            member = optionalMember.get();
        } else {
            // 신규 사용자 등록
            member = new Member();
            member.setEmail(email);
            member.setName(name);
            member.addRole(MemberRole.USER);
            // 필요한 경우 비밀번호와 역할 설정
            memberRepository.save(member);
        }

        // JWT 토큰 생성
        TokenInfo tokenInfo = jwtTokenProvider.generateToken(member.getEmail(), member.getName(), member.getMemberRoleList());

        // Refresh Token을 HttpOnly 쿠키에 저장
        Cookie refreshTokenCookie = new Cookie("refreshToken", tokenInfo.getRefreshToken());
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(60 * 60 * 24); // 1일
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true); // HTTPS 사용 시 true로 설정
        response.addCookie(refreshTokenCookie);

        // Access Token을 응답으로 반환
        return ResponseEntity.ok(Map.of("accessToken", tokenInfo.getAccessToken()));
    }
}
