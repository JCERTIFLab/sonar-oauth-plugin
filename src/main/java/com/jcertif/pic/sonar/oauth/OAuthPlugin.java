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
import java.util.List;
import org.sonar.api.ExtensionProvider;
import org.sonar.api.ServerExtension;
import org.sonar.api.SonarPlugin;
import org.sonar.api.config.Settings;

/**
 *
 * @author Martial SOMDA
 * @since 1.0
 */
public class OAuthPlugin extends SonarPlugin {

    @Override
    public List getExtensions() {
        return ImmutableList.of(OAuthPluginExtensionPoints.class);
    }

    public static final class OAuthPluginExtensionPoints extends ExtensionProvider implements ServerExtension {

        private Settings settings;

        public OAuthPluginExtensionPoints(Settings settings) {
            this.settings = settings;
        }

        @Override
        public Object provide() {
            List<Class> extensions = Lists.newArrayList();
            if (isRealmEnabled()) {
                Preconditions.checkState(settings.getBoolean("sonar.authenticator.createUsers"), "Property sonar.authenticator.createUsers must be set to true.");
                extensions.add(OAuthSecurityRealm.class);
                extensions.add(getOAuthClientExtension());
                extensions.add(OAuthAuthenticator.class);
                extensions.add(OAuthValidationFilter.class);
                extensions.add(OAuthAuthenticationFilter.class);
                extensions.add(OAuthLogoutFilter.class);
            }
            return extensions;
        }

        private boolean isRealmEnabled() {
            return OAuthSecurityRealm.NAME.equalsIgnoreCase(settings.getString("sonar.security.realm"));

        }

        private Class<? extends OAuthClient> getOAuthClientExtension() {
            Class<? extends OAuthClient> clazz = null;
            switch (settings.getString("sonar.oauth.providerId")) {
                case GithubClient.NAME:
                    clazz = GithubClient.class;
                    break;
                case GoogleClient.NAME:
                    clazz = GoogleClient.class;
                    break;
            }
            return clazz;
        }
    }
}
