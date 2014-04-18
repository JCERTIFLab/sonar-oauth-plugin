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

import com.google.common.base.Strings;

/**
 *
 * @author Martial SOMDA
 * @since 1.0
 */
public class OAuthQueryParams {

    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String REDIRECT_URI = "redirect_uri";
    public static final String SCOPE = "scope";
    public static final String RESPONSE_TYPE = "response_type";
    public static final String STATE = "state";
    public static final String GRANT_TYPE = "grant_type";
    public static final String AUTHORIZATION_CODE = "authorization_code";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String ERROR = "error";
    public static final String CODE = "code";
    public static final String TOKEN_TYPE = "token_type";
    public static final String EXPIRES_IN = "expires_in";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String ACCESS_DENIED = "access_denied";

    public static class Builder {

        private String baseParams;
        private String clientId;
        private String clientSecret;
        private String redirectUri;
        private String scope;
        private String state;
        private String responseType;
        private String code;
        private String grantType;

        public Builder() {
            this("");
        }

        public Builder(String baseParams) {
            this.baseParams = baseParams;
        }

        public Builder withClientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder withClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public Builder withRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        public Builder withScope(String scope) {
            this.scope = scope;
            return this;
        }

        public Builder withState(String state) {
            this.state = state;
            return this;
        }

        public Builder withResponseType(String responseType) {
            this.responseType = responseType;
            return this;
        }

        public Builder withCode(String code) {
            this.code = code;
            return this;
        }

        public Builder withGrantType(String grantType) {
            this.grantType = grantType;
            return this;
        }
        
        public String build() {
            String result = baseParams;
            StringBuilder queryString = new StringBuilder();
            addIfExists(queryString, CLIENT_ID, clientId);
            addIfExists(queryString, CLIENT_SECRET, clientSecret);
            addIfExists(queryString, REDIRECT_URI, redirectUri);
            addIfExists(queryString, SCOPE, scope);
            addIfExists(queryString, STATE, state);
            addIfExists(queryString, RESPONSE_TYPE, responseType);
            addIfExists(queryString, CODE, code);
            addIfExists(queryString, GRANT_TYPE, grantType);
            
            if (!Strings.isNullOrEmpty(queryString.toString())) {
                result += queryString.toString();
            }
            return result;
        }

        private void addIfExists(StringBuilder params, String key, String value) {
            if (!Strings.isNullOrEmpty(value)) {
                params.append("&").append(key).append("=").append(value);
            }
        }
    }
}
