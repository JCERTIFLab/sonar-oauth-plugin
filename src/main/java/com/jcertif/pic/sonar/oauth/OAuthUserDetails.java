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

import com.google.common.base.Objects;
import org.sonar.api.security.UserDetails;

/**
 * Created by Jean Blanchard on 15/10/14.
 */
public class OAuthUserDetails {
  private UserDetails details;
  private String login;

  public UserDetails getDetails() {
    return details;
  }

  public String getLogin() {
    return login;
  }

  @Override
  public String toString() {
      return Objects.toStringHelper(this)
              .add("login", login)
              .add("name", details.getName())
              .add("email", details.getEmail())
              .toString();
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private OAuthUserDetails instance;

    private Builder() {
      instance = new OAuthUserDetails();
      instance.details = new UserDetails();
    }

    public Builder login(String login) {
      instance.login = login;
      return this;
    }

    public Builder name(String name) {
      instance.details.setName(name);
      return this;
    }

    public Builder email(String email) {
      instance.details.setEmail(email);
      return this;
    }

    public OAuthUserDetails build() {
      return instance;
    }
  }
}
