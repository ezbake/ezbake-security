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
import ezbake.common.properties.EzProperties;
import ezbake.configuration.ClasspathConfigurationLoader;
import ezbake.configuration.EzConfiguration;
import ezbake.configuration.EzConfigurationLoaderException;
import ezbake.security.client.EzbakeSecurityClient;
import ezbake.thrift.ThriftClientPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

/**
 * User: jhastings
 * Date: 8/27/14
 * Time: 5:01 PM
 */
@Path("/ezsecurity")
public class EzSecurityWebApp {
    private static final Logger logger = LoggerFactory.getLogger(EzSecurityWebApp.class);



    @GET
    @Path("/test")
    public Response testServlet() {
        return Response.status(Response.Status.OK).build();
    }

}


