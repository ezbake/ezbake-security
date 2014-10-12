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
import java.lang.Exception;import java.lang.Runtime;import java.lang.String;import java.lang.System;import java.util.Map.Entry;

import ezbakehelpers.accumulo.AccumuloHelper;
import org.apache.accumulo.core.client.BatchWriter;
import org.apache.accumulo.core.client.Connector;
import org.apache.accumulo.core.client.MutationsRejectedException;
import org.apache.accumulo.core.client.Scanner;
import org.apache.accumulo.core.client.TableNotFoundException;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Mutation;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.Authorizations;
import org.apache.accumulo.core.security.ColumnVisibility;
import org.apache.hadoop.io.Text;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Iterator;
import java.util.Properties;
import java.util.concurrent.locks.Lock;

/**
 * @author gdrocella
 * @date 02/19/2014
 * @time 11:23am
 */
public class KeyManager {
	private String table;
	private Properties ezConfig;
	
	private static Logger log = LoggerFactory.getLogger(KeyManager.class);
	
	public static final String DEFAULT_TABLE_NAME = "ezbake_ezsecurity";
	public static final String PRIMARY_KEY = "symmetricKey";
	
	private Lock lock;

	public  KeyManager(Properties ezConfig, String table) throws Exception {
		this.ezConfig = ezConfig;
		this.table = table;
		
		try {
			Connector conn = new AccumuloHelper(ezConfig).getConnector();
			if(!conn.tableOperations().exists(table)) {
				throw new Exception("The table does not exist in the accumulo database you're attempting to connect to.");
			}
		}
		finally {
			
		}
	}
	
	public synchronized void registerSymmetricKey(byte[] cipherKeyData) {
		log.debug("Register Symmetric Key");
		
		try {
			Connector conn = new AccumuloHelper(ezConfig).getConnector();
			BatchWriter writer = conn.createBatchWriter(table, 100000, 1000, Runtime.getRuntime().availableProcessors());
			Mutation m = new Mutation(PRIMARY_KEY);
			
			Value keyObj = new Value(cipherKeyData);
			Text family = new Text("key");
			Text qualifier = new Text("qualify");
			ColumnVisibility colVis = new ColumnVisibility("public");
			long timestamp = System.currentTimeMillis();
			
			m.put(family, qualifier, colVis, timestamp, keyObj);
			writer.addMutation(m);
			writer.close();
			
		}
		catch(IOException e) {
			log.error("Error: " + e);
		}
		catch(TableNotFoundException e) {
			log.error("Error: " + e);
		}
		catch(MutationsRejectedException e) {
			log.error("Error: " + e);
		}
		finally {
			return;
		}
	}
	
	
	public synchronized byte[] getSymmetricKey() {
		byte[] cipherKeyData = null;
		
		log.debug("Get Symmetric Key");
		
		try {
			Connector conn = new AccumuloHelper(ezConfig).getConnector();
			Authorizations auths = new Authorizations("public");
			Scanner scan = conn.createScanner(this.table, auths);
			scan.fetchColumnFamily(new Text("key"));
			
			Iterator<Entry<Key,Value>> it = scan.iterator();
			
			log.debug("Retreived Key? " + it.hasNext());
			
			if(it.hasNext()) {
				Entry<Key,Value> entry = it.next();
				Value v = entry.getValue();
				cipherKeyData = v.get();
				log.debug("Key Value Retreived: " + new String(cipherKeyData, "UTF-8"));
			}
			
		}
		catch(IOException e) {
			e.printStackTrace();
		}
		catch(TableNotFoundException e) {
			e.printStackTrace();
		}
		finally {
			
		}
		
		
		return cipherKeyData;
	}
	
	
}
