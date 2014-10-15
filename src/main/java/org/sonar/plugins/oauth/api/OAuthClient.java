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
package org.sonar.plugins.oauth.api;

import com.jcertif.pic.sonar.oauth.OAuthPlugin;
import com.jcertif.pic.sonar.oauth.OAuthQueryParams;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

import com.jcertif.pic.sonar.oauth.OAuthUserDetails;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.ServerExtension;
import org.sonar.api.config.Settings;

/**
 *
 * @author Martial SOMDA
 * @since 1.0
 */
public abstract class OAuthClient implements ServerExtension {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthClient.class);

    public abstract String getName();

    public abstract String getUserInfoUrl();

    public abstract OAuthUserDetails buildUser(JSONObject jsonObject);

    public abstract String getAccessTokenMethod();

    public abstract Request createAuthenticationRequest();

    public abstract Request createAccessTokenRequest();
    
    protected Settings settings;

    public OAuthClient(Settings settings) {
        this.settings = settings;
    }

    public String getSonarServerUrl() {
        return settings.getString(OAuthPlugin.Settings.SONAR_SERVER_URL);
    }

    public OAuthUserDetails validate(Map<String, String[]> responseParameters) {
      OAuthUserDetails user = null;
        String accessToken = null;
        Request accessTokenRequest = createAccessTokenRequest();
        // if the user can authenticate we are good to go
        if ((responseParameters.get(OAuthQueryParams.ERROR) == null || responseParameters.get(OAuthQueryParams.ERROR).length == 0)
                && (accessToken = getAccessToken(accessTokenRequest.getUrl(), accessTokenRequest.getQueryParams(), getAccessTokenMethod(), responseParameters.get(OAuthQueryParams.CODE)[0])) != null) {
            user = getUser(getUserInfoUrl(), accessToken);
        } else {
            LOGGER.error("Failed to authenticate user.");
        }
        LOGGER.info("User : {}", user);
        return user;
    }

    protected String getAccessToken(String accessTokenUrl, String accesMethodParams, String accessTokenMethod, String code) {
        JSONObject jsonObject;
        if (Http.Methods.POST.equals(accessTokenMethod)) {
            jsonObject = doPost(accessTokenUrl, new OAuthQueryParams.Builder(accesMethodParams).withCode(code).build());
        } else {
            jsonObject = doGet(accessTokenUrl, new OAuthQueryParams.Builder(accesMethodParams).withCode(code).build());
        }
        return jsonObject.getString(OAuthQueryParams.ACCESS_TOKEN);
    }
    
    protected OAuthUserDetails getUser(String userInfoUrl, String accessToken) {
        OAuthUserDetails user = null;
        if (userInfoUrl != null && accessToken != null) {
            JSONObject jsonObject = doGet(userInfoUrl, "access_token=" + accessToken);
            user = buildUser(jsonObject);
        }
        return user;
    }

    protected JSONObject doGet(String url, String params) {
        if (url == null) {
            return null;
        }
        JSONObject jsonObject = null;
        final HttpClient client = new DefaultHttpClient();
        try {
            HttpGet request = new HttpGet(url + "?" + params);
            request.addHeader("Accept", "application/json");
            final HttpResponse response = client.execute(request);
            LOGGER.info("Response status is {} for url {}", response.getStatusLine(), url);
            jsonObject = processResponse(response);
        } catch (IOException e) {
            LOGGER.info("OAuth client was unable to perform authentication", e);
        }
        return jsonObject;
    }

    protected JSONObject doPost(String url, String params) {
        if (url == null) {
            return null;
        }
        JSONObject jsonObject = null;
        final HttpClient client = new DefaultHttpClient();
        try {
            HttpPost request = new HttpPost(url);
            request.setEntity(new StringEntity(params));
            request.addHeader("Accept", "application/json");
            request.addHeader("Content-Type", "application/x-www-form-urlencoded");
            final HttpResponse response = client.execute(request);
            LOGGER.info("Response status is {} for url {}", response.getStatusLine(), url);
            jsonObject = processResponse(response);
        } catch (IOException e) {
            LOGGER.info("OAuth client was unable to perform authentication", e);
        }
        return jsonObject;
    }

    protected JSONObject processResponse(final HttpResponse response) throws IOException, IllegalStateException, JSONException {
        JSONObject jsonObject = null;
        try {

            BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = rd.readLine()) != null) {
                result.append(line);
            }

            jsonObject = new JSONObject(result.toString());
            LOGGER.info("Response content is {} ", result);

        } finally {
            closeQuietly(response);
        }
        return jsonObject;
    }

    protected void closeQuietly(HttpResponse response) {
        if (response != null) {
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                try {
                    if (entity.isStreaming()) {
                        InputStream instream = entity.getContent();
                        if (instream != null) {
                            instream.close();
                        }
                    }
                } catch (final IOException ex) {
                }
            }
        }
    }

    public static class Request {

        private final String url;
        private final String queryParams;

        public Request(String url, String queryParams) {
            this.url = url;
            this.queryParams = queryParams;
        }

        public String getUrl() {
            return url;
        }

        public String getQueryParams() {
            return queryParams;
        }
    }

    public static final class Http {

        public final static class Status {

            public static final int OK = 200;
            public static final int INTERNAL_SERVER_ERROR = 500;
            public static final int BAD_REQUEST = 400;
            public static final int UNAUTHORIZED = 401;
            public static final int FORBIDDEN = 403;
        }

        public static final class Methods {

            public static final String GET = "GET";
            public static final String PU = "PUT";
            public static final String POST = "POST";
            public static final String DELETE = "DELETE";
        }
    }
}
