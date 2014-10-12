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

import com.google.common.io.Closeables;
import com.google.inject.Inject;
import ezbake.common.security.NoOpTextCryptoProvider;
import ezbake.crypto.AESCrypto;
import ezbake.crypto.PKeyCrypto;
import ezbake.crypto.PKeyCryptoException;
import ezbake.crypto.utils.EzSSL;
import ezbake.security.api.cache.EzSecurityCache;
import ezbake.security.common.core.SecurityConfigurationHelper;
import ezbake.security.util.KeyManager;
import ezbakehelpers.ezconfigurationhelpers.redis.RedisConfigurationHelper;
import ezbakehelpers.ezconfigurationhelpers.zookeeper.ZookeeperConfigurationHelper;
import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.framework.recipes.locks.InterProcessSemaphore;
import org.apache.curator.framework.recipes.locks.Lease;
import org.apache.curator.retry.RetryNTimes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.Properties;

/**
 * @author Gary Drocella
 * @date 01/29/14
 */
public class EzbakeDistributedCache<Key extends String, Value extends Serializable> implements EzSecurityCache<Key, Value> {
	private Jedis jedis;
	private int timeout;
	private static Logger log = LoggerFactory.getLogger(EzbakeDistributedCache.class);
	private PKeyCrypto crypto;
	
	public static final String DEFAULT_HOST = "localhost";
    public static final short DEFAULT_RPORT = 6379;
    public static final short DEFAULT_ZPORT = 2181;
	public static final int DEFAULT_TIMEOUT = 7200;
	
	private AESCrypto aesCrypto;

    private static final String keyPath = "/ezSecurity/cache/key";
	
	private KeyManager keyManager;
    private CuratorFramework framework;
    private InterProcessSemaphore mutex;

    public EzbakeDistributedCache(Properties ezConfiguration) {
        this(ezConfiguration, null, null);
    }

    @Inject
    public EzbakeDistributedCache(Properties ezConfiguration, Jedis jedis, SecretKey encryptionKey) {

        final ZookeeperConfigurationHelper zk = new ZookeeperConfigurationHelper(ezConfiguration);
        final SecurityConfigurationHelper sc = new SecurityConfigurationHelper(ezConfiguration, new NoOpTextCryptoProvider());
        final RedisConfigurationHelper jc = new RedisConfigurationHelper(ezConfiguration);

        this.timeout = (int) sc.getUserCacheTTL();
        this.aesCrypto = new AESCrypto();
        try {
            this.crypto = EzSSL.getCrypto(ezConfiguration);
        } catch (IOException e) {
            throw new RuntimeException("Unable to initalize: " + EzbakeDistributedCache.class.getCanonicalName(), e);
        }

        this.jedis = jedis;
        if (jedis == null) {
            this.jedis = new Jedis(jc.getRedisHost(), jc.getRedisPort());
        }
        if (!this.jedis.isConnected()) {
            this.jedis.connect();
        }

        framework = CuratorFrameworkFactory.builder().connectString(zk.getZookeeperConnectionString()).connectionTimeoutMs(100).sessionTimeoutMs(100).retryPolicy(new RetryNTimes(3,100)).build();
        framework.start();
        mutex = new InterProcessSemaphore(framework, keyPath, 1);

        SecretKey key = aesCrypto.generateAESKey();

        try {
            keyManager = new KeyManager(ezConfiguration, KeyManager.DEFAULT_TABLE_NAME);
            byte[] cipherKey = crypto.encrypt(key.getEncoded());

            Lease l = mutex.acquire();
            keyManager.registerSymmetricKey(cipherKey);
            mutex.returnLease(l);
        }
        catch(PKeyCryptoException e) {
            log.error("Error: " + e);
        }
        catch(Exception e) {
            log.error("Error: " + e);
            e.printStackTrace();
        }
    }


    public void setCrypto(PKeyCrypto crypto) {
        this.crypto = crypto;
    }

    public void put(Key key, Value info) {
        log.debug("put\nkey: " + key);

        byte[] value;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = null;
        try {
            out = new ObjectOutputStream(bos);
            out.writeObject(info);
            value = bos.toByteArray();

            SecretKey symKey = fetchSymmetricKey();
            byte[] encryptedData = aesCrypto.encrypt(symKey, value);

            Lease l = mutex.acquire();
            jedis.set(key.getBytes(),encryptedData);
            jedis.expire(key.getBytes(), timeout);
            mutex.returnLease(l);
        } catch (IOException e) {
            log.error("Unable to serialize cache value - {} won't be cached", key);
        } catch (Exception e) {
            log.error("Unable to serialize cache value - {} won't be cached", key);
        } finally {
            try {
                if (out != null) {
                    out.close();
                }
            } catch (IOException ex) {
                // ignore close exception
            }
            try {
                bos.close();
            } catch (IOException ex) {
                // ignore close exception
            }
        }
    }


    /**
     * @param key - key of the associated value in the (key,value) pair
     * @return - the value associated with specified key.
     */
    @Override
    public Value get(Key key, Class<?> clazz) {
        Value token = null;

        SecretKey symKey = fetchSymmetricKey();

        Lease l = null;
        ByteArrayInputStream bis = null;
        ObjectInput in = null;
        try {
            l = mutex.acquire();
            byte[] cipherValue = jedis.get(key.getBytes());
            mutex.returnLease(l);

            if (cipherValue != null) {
                token = (Value) clazz.newInstance();
                byte[] value = aesCrypto.decrypt(symKey, cipherValue);

                bis = new ByteArrayInputStream(value);
                in = new ObjectInputStream(bis);
                Object o = in.readObject();
                try {
                    token = (Value) o;
                } catch (ClassCastException e) {
                    log.error("Retrieved something for: {}, but couldn't deserialize it properly", key);
                }
            }
        } catch (Exception e) {
            log.error("Caught exception fetching: {}", key, e);
        } finally {
            try {
                Closeables.close(bis, true);
            } catch (IOException e) {
            }
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                }
            }
        }
        return token;
    }

    public SecretKey fetchSymmetricKey() {
    	SecretKey key = null;
    	
    	/**lock.lock();
    	byte[] cipherKey = jedis.get(keyName.getBytes());
    	lock.unlock();*/
    	
    	byte[] cipherKey = keyManager.getSymmetricKey();
    	
    	try {
    		byte[] symKey = crypto.decrypt(cipherKey);
    		
    		key = new SecretKeySpec(symKey, 0, symKey.length, "AES");
    		
    		//key = deserializeKey(symKey);
    	}
    	catch(PKeyCryptoException e) {
    		log.error("Error: " + e);
    	}
    	return key;
    }

    public byte[] serializeKey(SecretKey k) {
        byte[] data = null;

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(k);
            data = baos.toByteArray();
        } catch (IOException e) {
            log.error("");
        }

        return data;
    }
    
    public SecretKey deserializeKey(byte[] kdata) {
    	SecretKey k = null;
    	
    	try {
    		ByteArrayInputStream bais = new ByteArrayInputStream(kdata);
    		ObjectInputStream ois = new ObjectInputStream(bais);
    		k = (SecretKey)ois.readObject();
    	}
    	catch(IOException e) {
    		log.error("Error : " + e);
    	}
    	catch(ClassNotFoundException e) {
    		log.error("Error : " + e);
    	}
    	
    	return k;
    }
}
