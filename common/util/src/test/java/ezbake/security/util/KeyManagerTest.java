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

package ezbake.security.util;


import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Properties;

import ezbake.configuration.ClasspathConfigurationLoader;
import ezbake.configuration.EzConfiguration;
import ezbakehelpers.accumulo.AccumuloHelper;
import org.apache.accumulo.core.client.AccumuloException;
import org.apache.accumulo.core.client.AccumuloSecurityException;
import org.apache.accumulo.core.client.Connector;
import org.apache.accumulo.core.client.TableNotFoundException;
import org.junit.*;

public class KeyManagerTest {
	
	private KeyManager manager;

	private Properties ezConfig;

	@Before
	public void init() throws Exception {
        ezConfig = new EzConfiguration(new ClasspathConfigurationLoader()).getProperties();
        Connector connector = new AccumuloHelper(ezConfig).getConnector();
        connector.tableOperations().create(KeyManager.DEFAULT_TABLE_NAME);
        manager = new KeyManager(ezConfig, KeyManager.DEFAULT_TABLE_NAME);
	}
    @After
    public void cleanUp() throws IOException, AccumuloSecurityException, AccumuloException, TableNotFoundException {
        Connector connector = new AccumuloHelper(ezConfig).getConnector();
        connector.tableOperations().delete(KeyManager.DEFAULT_TABLE_NAME);
    }
	
	@Test
	public void testKeyManager() throws UnsupportedEncodingException {
		byte[] keyData = "TheKey".getBytes();
		manager.registerSymmetricKey(keyData);
		byte[] retrieveData = manager.getSymmetricKey();
        Assert.assertTrue(new String(keyData, "UTF-8").equals(new String(retrieveData, "UTF-8")));
	}
}
