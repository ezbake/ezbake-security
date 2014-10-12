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

import ezbake.security.api.cache.EzSecurityCache;
import org.apache.commons.collections.map.LRUMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.InvocationTargetException;
import java.util.Collections;
import java.util.Map;

/**
 * User: jhastings
 * Date: 2/6/14
 * Time: 11:17 AM
 */
public class MemoryCache<Key extends String, Value> implements EzSecurityCache<Key, Value> {
    private static Logger log = LoggerFactory.getLogger(MemoryCache.class);
    protected final Map<Key, CacheValue<Value>> lruCache;
    final long expiration;

    /*
     * Default values
     */
    private static final int DEFAULT_MAX_CAPACITY = 1000;
    private static final long DEFAULT_CACHE_EXPIRATION = 43200L;

    /**
     *
     * @param capacity
     * @param expiration in seconds
     */
    public MemoryCache(final int capacity, final long expiration) {
        // Enforce greater than zero policy
        int cap = (capacity > 0) ? capacity : DEFAULT_MAX_CAPACITY;
        long exp = (expiration > 0) ? expiration : DEFAULT_CACHE_EXPIRATION;

        lruCache = (Map<Key, CacheValue<Value>>) Collections.synchronizedMap(new LRUMap(cap));
        this.expiration = exp * 1000;

        log.debug("Initialized EzSecurity Cache\ncap:{}\nexp:{}", cap, exp);
    }

    /**
     *
     * @param expiration
     */
    public MemoryCache(final long expiration) {
        this(DEFAULT_MAX_CAPACITY, expiration);
    }

    /**
     * Constructor for ez.ez.EzSecurityCache
     *
     * @param capacity
     */
    public MemoryCache(final int capacity) {
        this(capacity, DEFAULT_CACHE_EXPIRATION);
    }

    @Override
    public void put(Key key, Value info) {
        log.debug("Storing '{}' from in EzSecurity Cache", key);
        lruCache.put(key, new CacheValue(info));
    }

    @Override
    public Value get(Key key, Class<?> clazz) {
        CacheValue<Value> value =  lruCache.get(key);
        Value retval = null;

        // check value expiration
        if (value != null && !expired(value.timestamp)) {
            log.info("Value for key: {} was not expired - returning the value", key);
            retval = (value.value != null)? value.value : null;
        } else if (value != null) {
            log.info("Value for key: {} expired at {} - removing from cache and returning null", key, value.timestamp);
            lruCache.remove(key);
        }

        // try to call the copy constructor so the user can't alter values in the cache
        if (retval != null) {
            try {
                Value copied = (Value) clazz.getDeclaredConstructor(clazz).newInstance(retval);
                retval = copied;
            } catch (NoSuchMethodException e) {
                log.warn("Cache value class doesn't support the copy constructor. Just returning the original object");
            } catch (InvocationTargetException e) {
                log.warn("Unexpected exception copying the cache value into a new object. returning null");
                retval = null;
            } catch (InstantiationException e) {
                log.warn("Unexpected exception instantiating the cache value into a new object. returning null");
                retval = null;
            } catch (IllegalAccessException e) {
                log.warn("Couldn't call the copy constructor of the cache value class. Just returning the original " +
                        "object");
            }
        }
        return retval;
    }

    private boolean expired(long timestamp) {
        return System.currentTimeMillis() >= (timestamp + this.expiration);
    }
}

class CacheValue<V> {
    public final long timestamp;
    public final V value;

    public CacheValue(V value) {
        this.timestamp = System.currentTimeMillis();
        this.value = value;
    }
}