package com.cos.security1.oauth;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.oauth.provider.FacebookUserInfo;
import com.cos.security1.oauth.provider.GoogleUserInfo;
import com.cos.security1.oauth.provider.NaverUserInfo;
import com.cos.security1.oauth.provider.OAuth2UserInfo;
import com.cos.security1.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    // 구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    // loadUser 메서드의 경우 기본적으로 자동으로 호출이 되지만
    // principalDetails 객체를 반환해주기 위해 오버라이드
    // 함수 종료시 @AuthenticationPrincipal 이 만들어진다
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("getClientRegistration -> {}", userRequest.getClientRegistration()); // registrationId로 어떤 OAuth로 로그인 했는지
        log.info("getAccessToken -> {}", userRequest.getAccessToken().getTokenValue());
        // 구글 로그인 버튼 클릭 -> 구글 로그인창 -> 로그인을 완료 -> code를 리턴 -> AccessToken 요청
        // userRequest 정보 -> loadUser 함수 호출 -> 구글로부터 회원프로필을 받아준다.

        OAuth2User oauth2User = super.loadUser(userRequest);
        log.info("getAttributes -> {}", oauth2User.getAttributes());

        OAuth2UserInfo oAuth2UserInfo = null;
        String clientName = userRequest.getClientRegistration().getClientName();

        if ("Google".equalsIgnoreCase(clientName)) {
            log.info("Google 로그인 요칭");
            oAuth2UserInfo = new GoogleUserInfo(oauth2User.getAttributes());
        } else if ("Facebook".equalsIgnoreCase(clientName)){
            log.info("Facebook 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oauth2User.getAttributes());
        } else if ("Naver".equalsIgnoreCase(clientName)){
            log.info("Naver 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map<String, Object>) oauth2User.getAttributes().get("response"));
        } else {
            log.info("We only support Google & Facebook & Naver");
        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);


        if (userEntity == null) {
            log.info("{} 로그인이 최초입니다.", clientName);

            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        } else {
            log.info("이미 {} 로그인한 기록이 있습니다.", clientName);
        }

        // 회원가입을 강제로 진행해볼 예정
        return new PrincipalDetails(userEntity, oauth2User.getAttributes());
    }
}
