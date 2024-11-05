package org.example.cookielogin.security.service;

import org.example.cookielogin.member.Member;
import org.example.cookielogin.member.MemberRepository;
import org.example.cookielogin.member.MemberRole;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final MemberRepository memberRepository;

    public CustomOAuth2UserService(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // OAuth2UserService를 통한 사용자 정보 로드
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        // provider 정보 가져오기
        String provider = userRequest.getClientRegistration().getRegistrationId();

        // 사용자 정보 추출
        String email = null;
        String name = null;
        String nickname = null;
        String profileImage = null;

        if ("kakao".equals(provider)) {
            Map<String, Object> attributes = oAuth2User.getAttributes();

            // properties에서 nickname과 profile_image 가져오기
            Map<String, Object> properties = (Map<String, Object>) attributes.get("properties");
            nickname = (String) properties.get("nickname");
            profileImage = (String) properties.get("profile_image");

            // kakao_account에서 email 가져오기
            Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
            email = (String) kakaoAccount.get("email");
        } else if ("google".equals(provider)) {
            email = oAuth2User.getAttribute("email");
            name = oAuth2User.getAttribute("name"); // Google의 이름
            profileImage = oAuth2User.getAttribute("picture"); // Google의 프로필 이미지
        } else if ("naver".equals(provider)) {
            Map<String, Object> attributes = oAuth2User.getAttributes();
            email = (String) attributes.get("email");
            name = (String) attributes.get("name");
            nickname = (String) attributes.get("nickname");
            profileImage = (String) attributes.get("profile_image");
        }

        // DB에 사용자 정보 저장 또는 업데이트
        Optional<Member> optionalMember = memberRepository.findByEmail(email);
        Member member;

        if (optionalMember.isPresent()) {
            member = optionalMember.get(); // 존재하는 회원 정보 가져오기
        } else {
            // 신규 사용자 등록
            member = new Member();
            member.setEmail(email);
            member.setName(name);
            member.setNickname(nickname);
            member.setProfileImage(profileImage);
            member.addRole(MemberRole.USER); // 기본 권한 설정
            memberRepository.save(member); // 신규 사용자 저장
        }

        // 사용자 정보 업데이트
        member.setName(name);
        member.setNickname(nickname);
        member.setProfileImage(profileImage);
        memberRepository.save(member);

        return oAuth2User; // OAuth2User를 반환
    }
}
