/*   Copyright (C) 2013-2014 Computer Sciences Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

package ezbake.security.examples.webapp;

import ezbake.base.thrift.EzSecurityTokenException;
import ezbake.base.thrift.ProxyPrincipal;
import ezbake.common.properties.EzProperties;
import ezbake.configuration.ClasspathConfigurationLoader;
import ezbake.configuration.EzConfiguration;
import ezbake.configuration.EzConfigurationLoaderException;
import ezbake.configuration.constants.EzBakePropertyConstants;
import ezbake.security.client.EzSecurityTokenWrapper;
import ezbake.security.client.EzbakeSecurityClient;
import ezbake.thrift.ThriftClientPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;

/**
 * User: jhastings
 * Date: 8/27/14
 * Time: 5:36 PM
 */
@Provider
@Priority(Priorities.AUTHENTICATION)
public class LoginFilter implements ContainerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(LoginFilter.class);

    private EzProperties ezProperties;
    private ThriftClientPool clientPool;
    private EzbakeSecurityClient securityClient;

    public LoginFilter() {
        try {
            ezProperties = new EzProperties(new EzConfiguration(new ClasspathConfigurationLoader()).getProperties(), true);
            ezProperties.setProperty(EzBakePropertyConstants.EZBAKE_CERTIFICATES_DIRECTORY,
                    LoginFilter.class.getResource("/pki").getFile());
        } catch (EzConfigurationLoaderException e) {
            logger.error("Failed to load EzConfiguration");
            ezProperties = new EzProperties();
        }

        clientPool = new ThriftClientPool(ezProperties);
        securityClient = new EzbakeSecurityClient(ezProperties, clientPool);
    }

    @Override
    public void filter(ContainerRequestContext containerRequestContext) throws IOException {

        try {
            ProxyPrincipal princiapl = securityClient.requestPrincipalFromRequest(containerRequestContext.getHeaders());
            EzSecurityTokenWrapper token = securityClient.fetchTokenForProxiedUser(princiapl, null);

            containerRequestContext.setProperty(token.getClass().getSimpleName(), token);

        } catch (EzSecurityTokenException e) {
            logger.error("Failed authentication with EzSecurity", e);
            containerRequestContext.abortWith(Response.status(Response.Status.FORBIDDEN).build());
        }
    }
}
