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

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ezbake.base.thrift.EzSecurityTokenException;
import ezbake.base.thrift.ProxyPrincipal;
import ezbake.base.thrift.ProxyUserToken;
import ezbake.common.properties.EzProperties;
import ezbake.configuration.ClasspathConfigurationLoader;
import ezbake.configuration.EzConfiguration;
import ezbake.configuration.EzConfigurationLoaderException;
import ezbake.security.client.EzSecurityTokenWrapper;
import ezbake.security.client.EzbakeSecurityClient;
import ezbake.security.common.core.EzSecurityTokenUtils;
import ezbake.thrift.ThriftClientPool;

/**
 * @author gdrocella
 * @date 09/17/14
 * Description: Second filter executed during filter phase.  This will parse the http headers and
 * set a session variable of the user principle token.
 */
public class LoginFilter implements Filter {

    private Logger logger = LoggerFactory.getLogger(LoginFilter.class);
    
    private EzProperties ezProperties;
    private ThriftClientPool clientPool;
    private EzbakeSecurityClient securityClient;
    
    public LoginFilter() {
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
    public void init(FilterConfig filterConfig) throws ServletException {
        
        
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        logger.debug("Doing Login Filter!");
        HttpServletRequest httpSr = (HttpServletRequest)request;
        HttpSession session = httpSr.getSession();
 
        try {
            ProxyPrincipal principal = securityClient.requestPrincipalFromRequest(httpSr);
            logger.debug("Proxy Token: {}", principal.getProxyToken());
            EzSecurityTokenWrapper token = securityClient.fetchTokenForProxiedUser(principal, null);
  
            session.setAttribute(EzbakeSecurityClient.SESSION_TOKEN, token);
        } catch (EzSecurityTokenException e) {
            logger.error("Error: Got an exception " + e);
        }
 
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // TODO Auto-generated method stub
        
    }

}
