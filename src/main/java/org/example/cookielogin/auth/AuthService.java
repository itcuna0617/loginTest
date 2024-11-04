package org.example.cookielogin.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.example.cookielogin.member.Member;
import org.example.cookielogin.member.MemberRepository;
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
import org.springframework.stereotype.Service;

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
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, user.get("pw"),
                userDetails.getAuthorities());

        // 인증 정보를 SecurityContextHolder에 설정(저장)
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 인증이 완료된 후 DB에 저장되어 있는 회원의 이메일, 비밀번호 검사
        Optional<Member> optionalMember = memberRepository.findByEmail(user.get("email"));

        Member member = optionalMember.orElseThrow(() -> new IllegalArgumentException("가입되지 않은 이메일입니다."));
        if(!passwordEncoder.matches(user.get("pw"), member.getPassword())){
            throw new IllegalArgumentException("이메일 또는 비밀번호가 일치하지 않습니다.");
        }

        log.info("로그인한 사용자: {}", member.getEmail());
        log.info("사용자 권한: {}", userDetails.getAuthorities());

        // Jwt 토큰 생성(인가)
        TokenInfo jwtToken = jwtTokenProvider.generateToken(member.getEmail(), member.getName(), member.getMemberRoleList());

        Map result = new HashMap();

        result.put("email : ", member.getEmail());
        result.put("name : ", member.getName());
        result.put("roles : ", member.getMemberRoleList());
        result.put("accessToken : ", jwtToken.getAccessToken());

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

}
