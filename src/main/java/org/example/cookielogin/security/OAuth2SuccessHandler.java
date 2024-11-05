package org.example.cookielogin.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.example.cookielogin.member.Member;
import org.example.cookielogin.member.MemberRepository;
import org.example.cookielogin.security.dto.TokenInfo;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Log4j2
@Component
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtTokenProvider tokenProvider;
    private final MemberRepository memberRepository;

    public OAuth2SuccessHandler(JwtTokenProvider tokenProvider, MemberRepository memberRepository) {
        this.tokenProvider = tokenProvider;
        this.memberRepository = memberRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {
        String userId = authentication.getName();

        Optional<Member> optionalMember = memberRepository.findByEmail(userId);
        Member member;

        member = optionalMember.get();

        // JWT 토큰 생성
        TokenInfo tokenInfo = tokenProvider.generateToken(member.getEmail(), member.getName(), member.getMemberRoleList());

        String accessToken = tokenInfo.getAccessToken();
        String refreshToken = tokenInfo.getRefreshToken();

        log.info("Access token: " + tokenInfo.getAccessToken());
        log.info("Refresh token: " + tokenInfo.getRefreshToken());

        // Refresh Token을 쿠키에 저장
        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60);

        response.addCookie(refreshTokenCookie);
        response.setHeader("Authorization", "Bearer " + accessToken);
    }
}
