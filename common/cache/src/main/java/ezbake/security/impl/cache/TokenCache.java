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

import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.CacheStats;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableMap;

import ezbake.base.thrift.EzSecurityToken;
import ezbake.security.api.cache.EzSecurityCache;

public class TokenCache<K, V> implements EzSecurityCache<K, V> {
	
	/* Time to Expire in Milliseconds */
	private long milliExpire;
	
	/* Guava Cache */
	private Cache<K, V> cache;
	
	/* Maximum Cache Size of this instance */
	private int maxSize;
	

	public static final long DEFAULT_CACHE_TTL = 2*60*60*1000;
	
	public static final int DEFAULT_MAX_CACHE_SIZE = 1000;

	/**
	 * Default Constructor
	 */
	public TokenCache() {
		this(DEFAULT_MAX_CACHE_SIZE, DEFAULT_CACHE_TTL);
	}
	
	/**
	 * Overloaded Constructor
	 * @param maxSize
	 */
	public TokenCache(int maxSize) {
		this(maxSize, DEFAULT_CACHE_TTL);
	}
	
	/**
	 * Overloaded Constructor
	 * @param milliExpire
	 */
	public TokenCache(long milliExpire) {
		this(DEFAULT_MAX_CACHE_SIZE, milliExpire);
	}
	
	/**
	 * Overloaded Constructor 
	 * @param maxSize - the maximum size of this cache instance
	 * @param milliExpire - the expiration time of a token in the cache in milliseconds
	 */
	public TokenCache(int maxSize, long milliExpire) {
		this.milliExpire = milliExpire;
		this.maxSize = maxSize;
		cache = CacheBuilder.newBuilder().maximumSize(maxSize)
				.expireAfterWrite(this.milliExpire, TimeUnit.MILLISECONDS)
				.build();
	}

	@Override
	public void put(K key, V info) {
		cache.put(key, info);
	}


	@Override
	public V get(K key, Class<?> clazz) {
		return cache.getIfPresent(key);
	}

}
