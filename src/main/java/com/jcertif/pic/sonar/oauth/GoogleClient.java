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
public class GoogleClient extends OAuthClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(GoogleClient.class);
    public static final String NAME = "google";
    private String googleUserInfoUrl = "https://www.googleapis.com/plus/v1/people/me";

    public GoogleClient(org.sonar.api.config.Settings settings) {
        super(settings);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getAccessTokenMethod() {
        return settings.getString(Settings.ACCESS_TOKEN_METHOD);
    }

    @Override
    public Request createAuthenticationRequest() {
        String authorizationUrl = settings.getString(Settings.AUTHORIZATION_URL);
        String clientId = settings.getString(Settings.CLIENT_ID);
        String scope = settings.getString(Settings.SCOPE);
        Preconditions.checkArgument(StringUtils.isNotBlank(authorizationUrl), "Property is missing : " + Settings.AUTHORIZATION_URL);
        Preconditions.checkArgument(!authorizationUrl.contains("?"), "Property must not contain the character ? : " + Settings.AUTHORIZATION_URL);
        Preconditions.checkArgument(!StringUtils.endsWith(authorizationUrl, "/"), "Property must not end with with slash / : " + Settings.AUTHORIZATION_URL);
        Preconditions.checkArgument(StringUtils.isNotBlank(clientId), "Property is missing : " + Settings.CLIENT_ID);

        return new Request(authorizationUrl, new OAuthQueryParams.Builder()
                .withClientId(clientId)
                .withScope("email")
                .withResponseType("code")
                .withRedirectUri(getSonarServerUrl())
                .withScope(scope)
                .build());
    }

    @Override
    public String getUserInfoUrl() {
        return googleUserInfoUrl;
    }

    @Override
    public void fillUser(JSONObject jsonObject, UserDetails user) {
        user.setEmail(jsonObject.getJSONArray("emails").getJSONObject(0).getString("value"));
        user.setName(jsonObject.getString("displayName"));
    }
    
    @Override
    public Request createAccessTokenRequest() {
        String clientId = settings.getString(Settings.CLIENT_ID);
        String clientSecret = settings.getString(Settings.CLIENT_SECRET);
        String accessTokenUrl = settings.getString(Settings.ACCESS_TOKEN_URL);
        Preconditions.checkArgument(StringUtils.isNotBlank(accessTokenUrl), "Property is missing : " + Settings.ACCESS_TOKEN_URL);
        Preconditions.checkArgument(!accessTokenUrl.contains("?"), "Property must not contain the character ? : " + Settings.ACCESS_TOKEN_URL);
        Preconditions.checkArgument(!StringUtils.endsWith(accessTokenUrl, "/"), "Property must not end with with slash / : " + Settings.ACCESS_TOKEN_URL);
        Preconditions.checkArgument(StringUtils.isNotBlank(clientId), "Property is missing : " + Settings.CLIENT_ID);
        Preconditions.checkArgument(StringUtils.isNotBlank(clientSecret), "Property is missing : " + Settings.CLIENT_SECRET);

        return new Request(accessTokenUrl, new OAuthQueryParams.Builder()
                .withClientId(clientId)
                .withClientSecret(clientSecret)
                .withRedirectUri(getSonarServerUrl() + "/oauth/" + getName())
                .withGrantType("authorization_code")
                .build());
    }

    public static final class Settings {

        public static final String AUTHORIZATION_URL = "sonar.google.authorizationUrl";
        public static final String ACCESS_TOKEN_URL = "sonar.google.accessTokenUrl";
        public static final String ACCESS_TOKEN_METHOD = "sonar.google.accessTokenMethod";
        public static final String AUTHORIZATION_URL_PARAMS = "sonar.google.authorizationUrlParams";
        public static final String ACCESS_TOKEN_URL_PARAMS = "sonar.google.accessTokenUrlParams";
        public static final String CLIENT_ID = "sonar.google.clientId";
        public static final String CLIENT_SECRET = "sonar.google.clientSecret";
        public static final String SCOPE = "sonar.google.scope";
    }
}
