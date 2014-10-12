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

package ezbake.security.client;

import com.google.common.base.Preconditions;
import ezbake.base.thrift.*;
import ezbake.configuration.ClasspathConfigurationLoader;
import ezbake.configuration.EzConfiguration;
import ezbake.configuration.constants.EzBakePropertyConstants;
import ezbake.local.zookeeper.LocalZookeeper;
import ezbake.security.client.provider.EzbakeTokenProvider;
import ezbake.security.common.core.EzSecurityTokenUtils;
import ezbake.security.impl.ua.FileUAService;
import org.apache.thrift.TException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.util.Properties;

import static org.junit.Assert.assertTrue;

/**
 * User: jhastings
 * Date: 7/14/14
 * Time: 2:36 PM
 */
public class FullyMockedProviderTest {
    private Logger log = LoggerFactory.getLogger(FullyMockedProviderTest.class);

    private Properties properties;
    private EzbakeSecurityClient client;

    LocalZookeeper localZookeeper;
    @Before
    public void init() throws Exception {
        URL certDirURL = FullyMockedProviderTest.class.getResource("/pki");
        URL usersURL = FullyMockedProviderTest.class.getResource("/users.json");

        Preconditions.checkNotNull(certDirURL);
        Preconditions.checkNotNull(usersURL);

        String certDir =  certDirURL.getFile();
        String userFile =  usersURL.getFile();

        EzConfiguration ezConfiguration = new EzConfiguration(new ClasspathConfigurationLoader());
        properties = ezConfiguration.getProperties();
        properties.setProperty(EzBakePropertyConstants.EZBAKE_CERTIFICATES_DIRECTORY, certDir);
        properties.setProperty(FileUAService.USERS_FILENAME, userFile);
        properties.setProperty(EzbakeTokenProvider.CLIENT_MODE, "Full");

        localZookeeper = new LocalZookeeper(9383);
        properties.setProperty(EzBakePropertyConstants.ZOOKEEPER_CONNECTION_STRING, localZookeeper.getConnectionString());
    }
    @After
    public void shutDown() throws IOException {
        if (localZookeeper != null) {
            localZookeeper.shutdown();
        }
    }

    @Test
    public void testAppInfoFull() throws EzSecurityTokenException, TException {
        client = new EzbakeSecurityClient(properties);
        EzSecurityToken token = client.fetchAppToken("SecurityClientTest");

        assertTrue(token != null);
        assertTrue(token.getType().equals(TokenType.APP));
    }

    @Test
    public void testUserInfoFull() throws EzSecurityTokenException, TException {
        client = new EzbakeSecurityClient(properties);

        ProxyUserToken userToken = new ProxyUserToken(new X509Info("Jim Bob"), "EzSecurity", "SecurityClientTest", System.currentTimeMillis()+1000);
        ProxyPrincipal pp = new ProxyPrincipal(EzSecurityTokenUtils.serializeProxyUserTokenToJSON(userToken), "Fake signature");
        EzSecurityToken token = client.fetchTokenForProxiedUser(pp, "SecurityClientTest");

        assertTrue(token != null);
        assertTrue(token.getType().equals(TokenType.USER));

    }

    @Test
    public void testFetchFull() throws EzSecurityTokenException, TException {
        client = new EzbakeSecurityClient(properties);

        ProxyUserToken userToken = new ProxyUserToken(new X509Info("Jim Bob"), "EzSecurity", "SecurityClientTest", System.currentTimeMillis()+1000);
        ProxyPrincipal pp = new ProxyPrincipal(EzSecurityTokenUtils.serializeProxyUserTokenToJSON(userToken), "Fake signature");

        EzSecurityToken token = client.fetchTokenForProxiedUser(pp, "SecurityClientTest");

        EzSecurityToken token2 = client.fetchDerivedTokenForApp(token, "SecurityClientTest");

        assertTrue(token2 != null);
        assertTrue(token2.getTokenPrincipal().getRequestChain().contains("SecurityClientTest"));

    }

}
