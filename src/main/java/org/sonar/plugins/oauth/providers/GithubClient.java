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
package org.sonar.plugins.oauth.providers;

import com.google.common.base.Preconditions;
import com.jcertif.pic.sonar.oauth.OAuthQueryParams;
import org.apache.commons.lang.StringUtils;
import org.json.JSONObject;
import org.sonar.api.Properties;
import org.sonar.api.Property;
import org.sonar.api.security.UserDetails;
import org.sonar.plugins.oauth.api.OAuthClient;
import org.sonar.plugins.oauth.api.OAuthClient.Request;

/**
 *
 * @author Martial SOMDA
 * @since 1.0
 */
@Properties({
    @Property(key = GithubClient.Settings.AUTHORIZATION_URL, name = "Authorization URL", defaultValue = "https://github.com/login/oauth/authorize"),
    @Property(key = GithubClient.Settings.ACCESS_TOKEN_URL, name = "Access Token URL", defaultValue = "https://github.com/login/oauth/access_token"),
    @Property(key = GithubClient.Settings.ACCESS_TOKEN_METHOD, name = "Access Token HTTP Method", defaultValue = "GET"),
    @Property(key = GithubClient.Settings.CLIENT_ID, name = "Client ID"),
    @Property(key = GithubClient.Settings.CLIENT_SECRET, name = "Client Secret"),
    @Property(key = GithubClient.Settings.SCOPE, name = "Scope", defaultValue = "user:email"),
    @Property(key = GithubClient.Settings.USER_INFO_URL, name = "User Information URL", defaultValue = "https://api.github.com/user")
})
public class GithubClient extends OAuthClient {

    public static final String NAME = "github";

    public GithubClient(org.sonar.api.config.Settings settings) {
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
                .withScope(scope)
                .build());
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
                .build());
    }

    @Override
    public String getUserInfoUrl() {
        return settings.getString(Settings.USER_INFO_URL);
    }

    @Override
    public void fillUser(JSONObject jsonObject, UserDetails user) {
        user.setEmail(jsonObject.getString("email"));
        user.setName(jsonObject.getString("name"));
    }

    public static final class Settings {

        public static final String AUTHORIZATION_URL = "sonar.github.authorizationUrl";
        public static final String ACCESS_TOKEN_URL = "sonar.github.accessTokenUrl";
        public static final String ACCESS_TOKEN_METHOD = "sonar.github.accessTokenMethod";
        public static final String CLIENT_ID = "sonar.github.clientId.secured";
        public static final String CLIENT_SECRET = "sonar.github.clientSecret.secured";
        public static final String SCOPE = "sonar.github.scope";
        public static final String USER_INFO_URL = "sonar.github.userInfoUrl";
    }
}
