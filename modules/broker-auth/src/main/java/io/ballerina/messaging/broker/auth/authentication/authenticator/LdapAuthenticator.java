/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package io.ballerina.messaging.broker.auth.authentication.authenticator;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import io.ballerina.messaging.broker.auth.AuthException;
import io.ballerina.messaging.broker.auth.BrokerAuthConfiguration;
import io.ballerina.messaging.broker.auth.authentication.AuthResult;
import io.ballerina.messaging.broker.auth.authentication.Authenticator;
import io.ballerina.messaging.broker.auth.ldap.LdapAuthHandler;
import io.ballerina.messaging.broker.common.StartupContext;
import io.ballerina.messaging.broker.common.config.BrokerConfigProvider;

import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nonnull;
import javax.naming.NamingException;

/**
 * Ldap authentication representation for @{@link Authenticator}.
 */
public class LdapAuthenticator implements Authenticator {

    private LdapAuthHandler ldapAuthHandler;
    private LoadingCache<String, String> userDistinguishedNames;

    /**
     * Cache loader for the userDistinguishedNames.
     */
    private class UserDnCacheLoader extends CacheLoader<String, String> {

        @Override
        public String load(@Nonnull String username) throws AuthException {
            try {
                return ldapAuthHandler.searchDN(username);
            } catch (NamingException e) {
                throw new AuthException("Error while searching username: " + username, e);
            }
        }
    }

    @Override
    public void initialize(StartupContext startupContext,
                           Map<String, Object> properties) throws Exception {

        BrokerConfigProvider configProvider = startupContext.getService(BrokerConfigProvider.class);
        BrokerAuthConfiguration brokerAuthConfiguration = configProvider.getConfigurationObject(
                BrokerAuthConfiguration.NAMESPACE, BrokerAuthConfiguration.class);
        BrokerAuthConfiguration.LdapConfiguration ldapConfiguration = brokerAuthConfiguration.getAuthentication()
                .getAuthenticator().getLdap();

        ldapAuthHandler = new LdapAuthHandler(ldapConfiguration);

        userDistinguishedNames = CacheBuilder.newBuilder()
                .maximumSize(ldapConfiguration.getCache().getSize())
                .expireAfterWrite(ldapConfiguration.getCache().getTimeout(), TimeUnit.MINUTES)
                .build(new UserDnCacheLoader());
    }

    @Override
    public AuthResult authenticate(String username, char[] password) throws AuthException {

        String dn;
        try {
            dn = userDistinguishedNames.get(username);
        } catch (ExecutionException e) {
            throw new AuthException("Error while retrieving dn from cache for username: " + username, e);
        }
        try {
            boolean isAuthenticated = ldapAuthHandler.authenticate(dn, password);
            return new AuthResult(isAuthenticated, username);
        } catch (NamingException e) {
            throw new AuthException("Error while authenticating Username: " + username, e);
        }
    }
}
