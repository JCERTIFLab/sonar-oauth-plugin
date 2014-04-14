/*
 * Sonar OAuth Plugin
 * Copyright (C) 2014 JCertif
 * lab@jcertif.org
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02
 */
package com.jcertif.pic.sonar.oauth;

import com.google.common.base.Preconditions;
import java.util.Map;
import org.apache.commons.lang.StringUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.security.UserDetails;

/**
 *
 * @author Martial SOMDA
 * @since 1.0
 */
public class GithubClient extends OAuthClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(GithubClient.class);
    public static final String NAME = "github";
    private String githubUserInfoUrl = "https://api.github.com/user?access_token=";

    public GithubClient(org.sonar.api.config.Settings settings) {
        super(settings);
    }

    @Override
    public String getName() {
        return NAME;
    }
    
    @Override
    public String createAuthenticationRequest() {
        String authorizationUrl = settings.getString(Settings.AUTHORIZATION_URL);
        String clientId = settings.getString(Settings.CLIENT_ID);
        Preconditions.checkArgument(StringUtils.isNotBlank(authorizationUrl), "Property is missing : " + Settings.AUTHORIZATION_URL);
        Preconditions.checkArgument(!authorizationUrl.contains("?"), "Property must not contain the character ? : " + Settings.AUTHORIZATION_URL);
        Preconditions.checkArgument(!StringUtils.endsWith(authorizationUrl, "/"), "Property must not end with with slash / : " + Settings.AUTHORIZATION_URL);
        Preconditions.checkArgument(StringUtils.isNotBlank(clientId), "Property is missing : " + Settings.CLIENT_ID);
        authorizationUrl += "?client_id=" + clientId + "&scope=user:email";
        return authorizationUrl;
    }

    @Override
    public UserDetails verify(Map<String,String[]> responseParameters) {
        UserDetails user = null;
        String accessToken = null;
        // if the user can authenticate we are good to go
        if ((responseParameters.get(OAuthParameter.ERROR) == null || responseParameters.get(OAuthParameter.ERROR).length == 0)
                && (accessToken = getAccessToken(responseParameters.get(OAuthParameter.CODE)[0])) != null) {
            user = getUser(accessToken);
        } else {
            LOGGER.error("Failed to authenticate user.");
        }
        LOGGER.info("User : {}", user);
        return user;
    }

    private String getAccessToken(final String code) {
        String accessToken = null;
        String clientId = settings.getString(Settings.CLIENT_ID);
        String clientSecret = settings.getString(Settings.CLIENT_SECRET);
        String accessTokenUrl = settings.getString(Settings.ACCESS_TOKEN_URL);
        Preconditions.checkArgument(StringUtils.isNotBlank(accessTokenUrl), "Property is missing : " + Settings.ACCESS_TOKEN_URL);
        Preconditions.checkArgument(!accessTokenUrl.contains("?"), "Property must not contain the character ? : " + Settings.ACCESS_TOKEN_URL);
        Preconditions.checkArgument(!StringUtils.endsWith(accessTokenUrl, "/"), "Property must not end with with slash / : " + Settings.ACCESS_TOKEN_URL);
        Preconditions.checkArgument(StringUtils.isNotBlank(clientId), "Property is missing : " + Settings.CLIENT_ID);
        Preconditions.checkArgument(StringUtils.isNotBlank(clientSecret), "Property is missing : " + Settings.CLIENT_SECRET);

        accessTokenUrl += "?client_id=" + clientId + "&client_secret=" + clientSecret + "&code=" + code;

        JSONObject jsonObject = doGetJson(accessTokenUrl);
        accessToken = jsonObject.getString(OAuthParameter.ACCESS_TOKEN);

        return accessToken;
    }

    private UserDetails getUser(String accessToken) {
        UserDetails user = null;
        if(accessToken != null){
            String userInfoUrl = githubUserInfoUrl + accessToken;
            JSONObject jsonObject = doGetJson(userInfoUrl);
            user = new UserDetails();
            user.setEmail(jsonObject.getString("email"));
            user.setName(jsonObject.getString("name"));
        }    
        return user;
    }

    public static final class Settings {
        public static  final String AUTHORIZATION_URL = "sonar.github.authorizationUrl";
        public static  final String ACCESS_TOKEN_URL = "sonar.github.accessTokenUrl";
        public static  final String AUTHORIZATION_URL_PARAMS = "sonar.github.authorizationUrlParams";
        public static  final String ACCESS_TOKEN_URL_PARAMS = "sonar.github.accessTokenUrlParams";
        public static  final String CLIENT_ID = "sonar.github.clientId";
        public static  final String CLIENT_SECRET = "sonar.github.clientSecret";
        public static  final String SCOPE = "sonar.github.scope";
    }
}
