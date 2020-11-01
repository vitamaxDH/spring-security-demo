package com.cos.security1.oauth.provider;

import lombok.Data;

import java.util.Map;

@Data
public class NaverUserInfo implements OAuth2UserInfo {

    private Map<String, Object> attributes; // getAttributes();

    public NaverUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getProvider() {
        return "Naver";
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }
}
