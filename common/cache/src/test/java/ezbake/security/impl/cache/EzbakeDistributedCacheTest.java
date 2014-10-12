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

package ezbake.security.impl.cache;

import ezbake.configuration.ClasspathConfigurationLoader;
import ezbake.configuration.EzConfiguration;
import ezbake.configuration.constants.EzBakePropertyConstants;
import ezbake.local.zookeeper.LocalZookeeper;
import ezbake.security.util.KeyManager;
import ezbakehelpers.accumulo.AccumuloHelper;
import org.apache.accumulo.core.client.Connector;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

public class EzbakeDistributedCacheTest {

	Properties config;
	EzbakeDistributedCache<String, String> cache;
	
	protected static String privateKeyPath = "src/test/resources/ezbakesecurity-key.pem";
	protected static String publicKeyPath = "src/test/resources/ezbakesecurity-pubkey.pem";
	
	private static Logger log = LoggerFactory.getLogger(EzbakeDistributedCacheTest.class);
	
	@Before
	public void init() throws Exception {
        config = new EzConfiguration(new ClasspathConfigurationLoader()).getProperties();

        config.setProperty(EzBakePropertyConstants.EZBAKE_CERTIFICATES_DIRECTORY, "src/test/resources/pki/server");
        config.setProperty(EzBakePropertyConstants.EZBAKE_CERTIFICATES_DIRECTORY, "EzbakeSecurityService");

        // Start the local zookeeper so we don't depend on it from outside
        LocalZookeeper zook = new LocalZookeeper();
        config.setProperty(EzBakePropertyConstants.ZOOKEEPER_CONNECTION_STRING, zook.getConnectionString());

        Connector conn = new AccumuloHelper(config).getConnector();
        if(!conn.tableOperations().exists(KeyManager.DEFAULT_TABLE_NAME)) {
            conn.tableOperations().create(KeyManager.DEFAULT_TABLE_NAME);
        }

        cache = new EzbakeDistributedCache<>(config);
	}
	
	@Test @Ignore
	public void multiThreadTest() {
		
		log.info("Beginning multiThreadTest");
		
		int numThreads = Runtime.getRuntime().availableProcessors();
		Thread[] threads = new Thread[numThreads];
		
		for(int i = 0; i < numThreads; i++) {
			threads[i] = new Thread(new Runnable() {

				@Override
				public void run() {
					
					log.debug("Running " + Thread.currentThread().getName());
					
					List<String> theList = new LinkedList<String>();
					
					for(int j = 0; j < 25; j++) {
						String s = "Thread " + j;
						String name = Thread.currentThread().getName() + "-" +  j;
						
						theList.add(name);
						cache.put(name, s);
						
					}
					
					for(String name : theList) {
						String info = cache.get(name, String.class);
						log.info("({} - {})", name, info);
					}
					
					assertTrue(theList.size() == 25);
				}

				private void assertTrue(boolean b) {
					// TODO Auto-generated method stub
					
				}
				
			});
			
			threads[i].setName("Thread" + i);
		}
		
		for(int i = 0; i < threads.length; i++) {
			threads[i].start();
		}
		
		for(int i = 0; i < threads.length; i++) {
			try {
				threads[i].join();
			}
			catch(InterruptedException e) {
				
			}
		}
	}
}
