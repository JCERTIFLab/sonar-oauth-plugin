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
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import java.util.Collection;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.reflections.Reflections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.CoreProperties;
import org.sonar.api.ExtensionProvider;
import org.sonar.api.Properties;
import org.sonar.api.Property;
import org.sonar.api.ServerExtension;
import org.sonar.api.SonarPlugin;
import org.sonar.plugins.oauth.api.OAuthClient;

/**
 *
 * @author Martial SOMDA
 * @since 1.0
 */
@Properties({
    @Property(key = OAuthPlugin.Settings.PROVIDER_ID, name = "OAuth Provider ID"),
    @Property(key = OAuthPlugin.Settings.SONAR_SERVER_URL, name = "Sonar Server URL", defaultValue = "http://localhost:9000")
})
public class OAuthPlugin extends SonarPlugin {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthPlugin.class);

    @Override
    public List getExtensions() {
        return ImmutableList.of(OAuthExtensions.class);
    }

    public static final class OAuthExtensions extends ExtensionProvider implements ServerExtension {

        private final org.sonar.api.config.Settings settings;
        private final Collection<Class<? extends OAuthClient>> oauthClients;

        public OAuthExtensions(org.sonar.api.config.Settings settings) {
            this.settings = settings;
            Reflections reflections = new Reflections("org.sonar.plugins.oauth.providers");
            this.oauthClients = reflections.getSubTypesOf(OAuthClient.class);
        }

        @Override
        public Object provide() {
            List<Class> extensions = Lists.newArrayList();
            if (isRealmEnabled()) {
                Preconditions.checkState(settings.getBoolean(CoreProperties.CORE_AUTHENTICATOR_CREATE_USERS), "Property sonar.authenticator.createUsers must be set to true.");
                Preconditions.checkArgument(StringUtils.isNotBlank(Settings.PROVIDER_ID), "Property is missing : " + Settings.PROVIDER_ID);
                extensions.add(OAuthSecurityRealm.class);
                extensions.add(getOAuthClient());
                extensions.add(OAuthAuthenticator.class);
                extensions.add(OAuthValidationFilter.class);
                extensions.add(OAuthAuthenticationFilter.class);
                extensions.add(OAuthLogoutFilter.class);
            }
            return extensions;
        }

        private boolean isRealmEnabled() {
            return OAuthSecurityRealm.NAME.equalsIgnoreCase(settings.getString(CoreProperties.CORE_AUTHENTICATOR_REALM));

        }

        private Class<? extends OAuthClient> getOAuthClient() {
            Class<? extends OAuthClient> clazz = null;
            LOGGER.info("Registered Clients : {}", oauthClients);
            for (Class<? extends OAuthClient> oauthClientClass : oauthClients) {
                if (settings.getString(Settings.PROVIDER_ID).equalsIgnoreCase(
                        oauthClientClass.getSimpleName().substring(0, oauthClientClass.getSimpleName().length() - "Client".length()))) {
                    clazz = oauthClientClass;
                }
            }
            if (null == clazz) {
                throw new IllegalArgumentException("Unsupported oauth provider : " + settings.getString(Settings.PROVIDER_ID));
            }
            return clazz;
        }
    }

    public static final class Settings {

        public static final String PROVIDER_ID = "sonar.oauth.providerId";
        public static final String SONAR_SERVER_URL = "sonar.oauth.sonarServerUrl";
        public static final String ADMIN_USERS = "sonar.oauth.adminUsers";
    }
}
