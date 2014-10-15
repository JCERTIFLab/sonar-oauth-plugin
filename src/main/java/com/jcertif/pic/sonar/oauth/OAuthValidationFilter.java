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

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import org.sonar.api.security.UserDetails;
import org.sonar.api.web.ServletFilter;
import org.sonar.plugins.oauth.api.OAuthClient;

/**
 *
 * @author Martial SOMDA
 * @since
 */
public class OAuthValidationFilter extends ServletFilter {

    private final OAuthClient oauthClient;

    public OAuthValidationFilter(OAuthClient oauthClient) {
        this.oauthClient = oauthClient;
    }

    @Override
    public UrlPattern doGetPattern() {
        return UrlPattern.create("/oauth/validate");
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        OAuthUserDetails user = oauthClient.validate(servletRequest.getParameterMap());
        HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

        if (user == null) {
            httpResponse.sendRedirect("/oauth/unauthorized");
        } else {
            servletRequest.setAttribute(OAuthUsersProvider.OAUTH_USER_KEY, user);
            filterChain.doFilter(servletRequest, servletResponse);
        }

    }

    @Override
    public void destroy() {
    }
}
