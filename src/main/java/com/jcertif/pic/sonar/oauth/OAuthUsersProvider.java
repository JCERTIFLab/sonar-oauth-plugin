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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.UserDetails;

/**
 *
 * @author Martial SOMDA
 * @since 1.0
 */
public class OAuthUsersProvider extends ExternalUsersProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthUsersProvider.class);
    public static final String OAUTH_USER_KEY = "oauth_user";

    @Override
    public UserDetails doGetUserDetails(Context context) {
        OAuthUserDetails user = (OAuthUserDetails) context.getRequest().getAttribute(OAUTH_USER_KEY);
        LOGGER.info("Stored user : {}", user);
        return user.getDetails();
    }

}
