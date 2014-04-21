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

import org.sonar.api.config.Settings;
import org.sonar.api.security.Authenticator;
import org.sonar.api.security.ExternalGroupsProvider;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.SecurityRealm;

/**
 *
 * @author Martial SOMDA
 * @since 1.0
 */
public class OAuthSecurityRealm extends SecurityRealm {

    public static final String NAME = "oauth";
    private final Settings settings;

    public OAuthSecurityRealm(Settings settings) {
        this.settings = settings;
    }

    @Override
    public Authenticator doGetAuthenticator() {
        return new OAuthAuthenticator();
    }

    @Override
    public ExternalUsersProvider getUsersProvider() {
        return new OAuthUsersProvider();
    }

    @Override
    public ExternalGroupsProvider getGroupsProvider() {
        return new OAuthGroupsProvider(settings);
    }

    @Override
    public String getName() {
        return NAME;
    }

}
