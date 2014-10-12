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
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * User: jhastings
 * Date: 9/27/13
 * Time: 10:59 AM
 */
public class MemoryCacheTest {

    @Test
    public void testCacheExpired() {
        EzSecurityCache<String, String> cache = new MemoryCache<String, String>(4, 1);
        String user = "test";
        cache.put("Test", user);
        try {
            Thread.sleep(1 * 1000);
            String shouldBeNull = cache.get("Test", String.class);
            assertNull("Cache should be expired", shouldBeNull);
        } catch (InterruptedException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testCacheLastsExpirationLength() {
        EzSecurityCache<String, String> cache = new MemoryCache<String, String>(4, 2);
        String user = "Test";

        cache.put("Test", user);
        try {
            Thread.sleep(1 * 1000);
            String shouldBeNull = cache.get("Test", String.class);
            assertNotNull("Cache should not be expired", shouldBeNull);
        } catch (InterruptedException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void cacheOverflow() {
        EzSecurityCache<String, String> cache = new MemoryCache<String, String>(10);

        for (int i = 0; i < 10; ++i) {
            String user = ""+i;
            cache.put("" + i, user);
        }

        cache.put("New", "expired");

        String expired = cache.get("0", String.class);
        assertNull("Oldest element in cache should be expired", expired);
    }
}
