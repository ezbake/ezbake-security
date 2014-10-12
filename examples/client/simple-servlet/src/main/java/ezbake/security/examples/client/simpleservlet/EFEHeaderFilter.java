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

import ezbake.base.thrift.ProxyUserToken;
import ezbake.base.thrift.X509Info;
import ezbake.security.client.EzbakeSecurityClient;
import ezbake.security.common.core.EzSecurityTokenUtils;

import org.apache.thrift.TException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

/**
 * User: jhastings
 * Date: 8/28/14
 * Time: 10:20 AM
 */
public class EFEHeaderFilter implements Filter {
    private static final Logger logger = LoggerFactory.getLogger(EFEHeaderFilter.class);
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(final ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        final HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
        HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(httpRequest) {
            @Override
            public String getHeader(String name) {
                
                ProxyUserToken token = new ProxyUserToken(
                        new X509Info("CN=Mock User"),
                        "EzSecurity",
                        "EFE", System.currentTimeMillis()+30000);
                
                if (name.equals(EzbakeSecurityClient.EFE_USER_HEADER)) {
                    try {
                        logger.debug("Filter Proxy Token {}", EzSecurityTokenUtils.serializeProxyUserTokenToJSON(token));
                        return EzSecurityTokenUtils.serializeProxyUserTokenToJSON(token);
                    } catch (TException e) {
                        logger.error("Error {}", e);
                    }
                } else if (name.equals(EzbakeSecurityClient.EFE_SIGNATURE_HEADER)) {
                    return "";
                }
                
                return super.getHeader(name);
            }
            
            @Override
            public Enumeration<String> getHeaderNames() {
                List<String> l = Collections.list(super.getHeaderNames());
                if(l == null) {
                    l = new LinkedList<String>();
                }
                l.add(EzbakeSecurityClient.EFE_SIGNATURE_HEADER);
                l.add(EzbakeSecurityClient.EFE_USER_HEADER);
                return Collections.enumeration(l);
            }
            
            
        };
        filterChain.doFilter(wrapper, servletResponse);
    }

    @Override
    public void destroy() {

    }
}
