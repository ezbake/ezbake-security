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

package ezbake.security.persistence.model;

import static org.junit.Assert.*;

import org.apache.accumulo.core.data.Mutation;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AppPersistenceModelTest {
    
    private Logger log = LoggerFactory.getLogger(AppPersistenceModelTest.class);
    @BeforeClass
    public static void init() {
        
    }
    
    @Test
    public void testPrivateKeyEncryptionDecryption() throws AppPersistCryptoException {
        AppPersistenceModel model = new AppPersistenceModel();
        String dummyKey = "dummy";
        
        for(int i = 0; i <= 4; i++) {
            model.setId("0" + i);
            model.setPrivateKey(dummyKey);
            String rtv = model.getPrivateKey();
        
            log.debug("Private Key {}" , rtv);
        
            assertTrue(rtv,dummyKey.equals(rtv));
        }
    }
    
    @Test
    public void testPrivateKeyMutation() throws AppPersistCryptoException {
        AppPersistenceModel model = new AppPersistenceModel();
        String dummyKey = "dummy";
        model.setId("01");
        Mutation m = model.getPrivateKeyMutation("01", dummyKey.getBytes());
        log.debug(m.toString());
    }
}
