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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.ServerExtension;
import org.sonar.api.config.Settings;
import org.sonar.api.security.UserDetails;

/**
 *
 * @author Martial SOMDA
 * @since 1.0
 */
public abstract class OAuthClient implements ServerExtension {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthClient.class);
    public static  final String SONAR_SERVER_URL = "sonar.oauth.sonarServerUrl";
    
    public abstract String getName();
    
    public abstract String createAuthenticationRequest();

    public abstract UserDetails verify(Map<String, String[]> responseParameters);
    
    protected Settings settings;

    public OAuthClient(Settings settings) {
        this.settings = settings;
    }
    
    public String getSonarServerUrl(){
        return settings.getString(SONAR_SERVER_URL);
    }
    protected JSONObject doGetJson(String url) {

        if (url == null) {
            return null;
        }
        JSONObject jsonObject = null;
        final HttpClient client = new DefaultHttpClient();
        try {;
            HttpGet request = new HttpGet(url);
            request.addHeader("accept", "application/json");
            final HttpResponse response = client.execute(request);

            try {
                LOGGER.info("Response status is {} for url {}", response.getStatusLine(), url);

                if (response.getStatusLine().getStatusCode() == 200) {
                    BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
                    StringBuilder result = new StringBuilder();
                    String line = "";
                    while ((line = rd.readLine()) != null) {
                        result.append(line);
                    }

                    jsonObject = new JSONObject(result.toString());
                    LOGGER.info("Response content is {} ", result);
                }

            } finally {
                closeQuietly(response);
            }
        } catch (IOException e) {
            LOGGER.info("URL Realm was unable to perform authentication", e);
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
}
