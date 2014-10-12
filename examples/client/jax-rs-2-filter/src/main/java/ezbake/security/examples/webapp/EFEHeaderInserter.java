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

import ezbake.base.thrift.ProxyUserToken;
import ezbake.base.thrift.X509Info;
import ezbake.security.client.EzbakeSecurityClient;
import ezbake.security.common.core.EzSecurityTokenUtils;
import org.apache.thrift.TException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.ext.Provider;
import java.io.IOException;

/**
 * This class is a filter that mimics the role of the EzFrontend in the request chain. It inserts the
 * user info headers.
 *
 * User: jhastings
 * Date: 8/27/14
 * Time: 9:52 PM
 */
@Provider
@Priority(100)
public class EFEHeaderInserter implements ContainerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(EFEHeaderInserter.class);

    @Override
    public void filter(ContainerRequestContext containerRequestContext) throws IOException {
        ProxyUserToken token = new ProxyUserToken(
                new X509Info("Jeff"),
                "EzSecurity",
                "EFE", System.currentTimeMillis()+30000);
        try {
            containerRequestContext.getHeaders().add(EzbakeSecurityClient.EFE_USER_HEADER,
                    EzSecurityTokenUtils.serializeProxyUserTokenToJSON(token));
            containerRequestContext.getHeaders().add(EzbakeSecurityClient.EFE_SIGNATURE_HEADER, "");
        } catch (TException e) {
            logger.warn("Failed serializing proxy user token. Headers will not be available in this request");
        }
    }
}
