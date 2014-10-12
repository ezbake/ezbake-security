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

package ezbake.security.examples.client.simpleservlet;

import ezbake.base.thrift.EzSecurityTokenException;
import ezbake.base.thrift.ProxyPrincipal;
import ezbake.common.properties.EzProperties;
import ezbake.configuration.ClasspathConfigurationLoader;
import ezbake.configuration.EzConfiguration;
import ezbake.configuration.EzConfigurationLoaderException;
import ezbake.security.client.EzSecurityTokenWrapper;
import ezbake.security.client.EzbakeSecurityClient;
import ezbake.thrift.ThriftClientPool;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * User: jhastings
 * Date: 8/28/14
 * Time: 9:50 AM
 */
public class EzSecurityClientServlet extends HttpServlet {
    private static final Logger logger = LoggerFactory.getLogger(EzSecurityClientServlet.class);

    private EzProperties ezProperties;
    private ThriftClientPool clientPool;
    private EzbakeSecurityClient securityClient;

    public EzSecurityClientServlet() {
        try {
            ezProperties = new EzProperties(new EzConfiguration(new ClasspathConfigurationLoader()).getProperties(), true);
        } catch (EzConfigurationLoaderException e) {
            logger.error("Failed to load EzConfiguration");
            ezProperties = new EzProperties();
        }

        clientPool = new ThriftClientPool(ezProperties);
        securityClient = new EzbakeSecurityClient(ezProperties, clientPool);
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession();
        EzSecurityTokenWrapper tokWrapper = (EzSecurityTokenWrapper)session.getAttribute(EzbakeSecurityClient.SESSION_TOKEN);
        logger.debug("User id from session: {}", tokWrapper.getUserId());
    }
}
