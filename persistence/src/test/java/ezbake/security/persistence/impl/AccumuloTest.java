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

package ezbake.security.persistence.impl;

import ezbake.configuration.EzConfigurationLoaderException;
import ezbake.security.persistence.model.AppPersistCryptoException;
import ezbake.security.persistence.model.AppPersistenceModel;
import ezbake.security.thrift.RegistrationException;
import ezbake.security.thrift.RegistrationStatus;
import ezbake.security.thrift.SecurityIDNotFoundException;

import org.apache.accumulo.core.client.AccumuloException;
import org.apache.accumulo.core.client.AccumuloSecurityException;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * User: jhastings
 * Date: 5/2/14
 * Time: 11:56 AM
 */
public class AccumuloTest extends TestRegistrationManager {
    AccumuloRegistrationManager accumulo;

    @Override
    public void setUp() throws AccumuloSecurityException, AccumuloException, IOException, RegistrationException, EzConfigurationLoaderException {
        super.setUp();
        accumulo = (AccumuloRegistrationManager)reg;

        accumulo.writeRegistration(caRegistration());
    }

    @Test
    public void testRegister() throws RegistrationException, SecurityIDNotFoundException {
        Set<String> admins = new HashSet<String>();
        admins.addAll(Arrays.asList("John", "Joffrey"));

        accumulo.register("123456", "Jeff", "AppName", "low", Arrays.asList("official", "USA", "T"), admins, "App Dn 1");
        accumulo.register("789111", "Jeff", "AppName2", "low", Arrays.asList("official", "USA", "T"), admins, "App Dn 2");
        accumulo.register("456789", "Frank", "Franks app", "high", Arrays.asList("official", "USA") , admins, "App Dn 3");

        AppPersistenceModel reg = accumulo.getRegistration(new String[]{"low"}, "123456", null, RegistrationStatus.PENDING);
        Assert.assertEquals("123456", reg.getId());
        Assert.assertEquals("AppName", reg.getAppName());
        Assert.assertEquals("low", reg.getVisibilityLevel());
        Assert.assertArrayEquals(new String[]{"official", "USA", "T"}, reg.getVisibility().toArray());
        Assert.assertEquals(RegistrationStatus.PENDING, reg.getStatus());
        Assert.assertEquals("Jeff", reg.getOwner());
        Assert.assertArrayEquals(new String[]{"John", "Joffrey"}, reg.getAdmins().toArray());

        AppPersistenceModel frank = accumulo.getRegistration(new String[]{"low"}, "456789", null, RegistrationStatus.PENDING);
        Assert.assertEquals("456789", frank.getId());
        Assert.assertEquals("Franks app", frank.getAppName());
        Assert.assertEquals("high", frank.getVisibilityLevel());
        Assert.assertArrayEquals(new String[]{"official", "USA"}, frank.getVisibility().toArray());
        Assert.assertEquals(RegistrationStatus.PENDING, frank.getStatus());
        Assert.assertEquals("Frank", frank.getOwner());
        Assert.assertArrayEquals(new String[]{"John", "Joffrey"}, frank.getAdmins().toArray());
    }

    protected AppPersistenceModel caRegistration() {
        AppPersistenceModel m = new AppPersistenceModel();
        m.setId("00");
        m.setX509Cert("CA CERTIFICATE");
        return m;
    }
    @Test
    public void testCaGet() throws RegistrationException, SecurityIDNotFoundException, AppPersistCryptoException {
        AppPersistenceModel m = reg.getRegistration(scanAuths, "00", null, null);
        Assert.assertEquals("00", m.getId());
        Assert.assertEquals("CA CERTIFICATE", m.getX509Cert());
        Assert.assertNull(m.getAppName());
        Assert.assertNull(m.getPrivateKey());
    }

}
