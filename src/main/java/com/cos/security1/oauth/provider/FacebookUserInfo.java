package com.cos.security1.oauth.provider;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
public class FacebookUserInfo implements OAuth2UserInfo {

    private Map<String, Object> attributes; // getAttributes();

    public FacebookUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getProvider() {
        return "Facebook";
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
