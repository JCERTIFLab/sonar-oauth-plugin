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

import com.google.common.collect.Sets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.Properties;
import org.sonar.api.Property;
import org.sonar.api.config.Settings;
import org.sonar.api.security.DefaultGroups;
import org.sonar.api.security.ExternalGroupsProvider;

/**
 *
 * @author Martial SOMDA
 * @since 1.0
 */
@Properties(
        @Property(key = OAuthPlugin.Settings.ADMIN_USERS, name = "Admin Users")
)
public class OAuthGroupsProvider extends ExternalGroupsProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthGroupsProvider.class);

    private final Collection<String> adminUsers;

    public OAuthGroupsProvider(Settings settings) {
        this.adminUsers = Arrays.asList(settings.getStringArray(OAuthPlugin.Settings.ADMIN_USERS));
    }

    @Override
    public Collection<String> doGetGroups(String username) {
        Set<String> groups = Sets.newHashSet();
        if (adminUsers.contains(username)) {
            LOGGER.info("Authenticated admin user {}", username);
            groups.add(DefaultGroups.ADMINISTRATORS);
        } else {
            groups.add(DefaultGroups.USERS);
        }
        return groups;
    }

}
