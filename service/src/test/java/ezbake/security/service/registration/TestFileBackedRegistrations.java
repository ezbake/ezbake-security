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

package ezbake.security.service.registration;

import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.Properties;

/**
 * User: jhastings
 * Date: 10/7/13
 * Time: 4:21 PM
 */
public class TestFileBackedRegistrations {
    @Test
    public void testReg() throws IOException {
        FileBackedRegistrations regs = new FileBackedRegistrations(new Properties());

        //test for class jar json file
        AppInstance reg = regs.getClient("EzPy");
        Assert.assertTrue(reg.getRegistration().getAppName().equals("EzPy"));
        Assert.assertEquals("med", reg.getRegistration().getVisibilityLevel());
        Assert.assertArrayEquals(new String[] {"ezbake", "42six", "python", "snakes"},
                reg.getRegistration().getVisibility().toArray());

        reg = regs.getClient("ExSearch");
        Assert.assertTrue(reg.getRegistration().getAppName().equals("ExSearch"));
        Assert.assertEquals("high", reg.getRegistration().getVisibilityLevel());
        Assert.assertArrayEquals(new String[] {"42six", "admins", "leaders"},
                reg.getRegistration().getVisibility().toArray());
    }

    @Test
    public void testWithClass() throws IOException {
        String app = "SecurityClientTest";
        FileBackedRegistrations regs = new FileBackedRegistrations(new Properties());

        AppInstance reg = regs.getClient(app);
        Assert.assertEquals(app, reg.getRegistration().getAppName());
        Assert.assertEquals("high", reg.getRegistration().getVisibilityLevel());
        Assert.assertArrayEquals(new String[] {"ezbake", "42six", "CSC", "USA"},
                reg.getRegistration().getVisibility().toArray());
    }
}
