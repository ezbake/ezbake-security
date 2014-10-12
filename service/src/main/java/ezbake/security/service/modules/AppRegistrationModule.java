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

package ezbake.security.service.modules;

import com.google.inject.AbstractModule;
import ezbake.configuration.constants.EzBakePropertyConstants;
import ezbake.security.service.registration.EzbakeRegistrationService;
import ezbake.security.service.registration.FileBackedRegistrations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

/**
 * User: jhastings
 * Date: 7/15/14
 * Time: 9:05 AM
 */
public class AppRegistrationModule extends AbstractModule {
    private static final Logger LOGGER = LoggerFactory.getLogger(AppRegistrationModule.class);

    Properties properties;
    public AppRegistrationModule(Properties ezConfiguration) {
        this.properties = ezConfiguration;
    }

    @Override
    protected void configure() {
        String impl = properties.getProperty(EzBakePropertyConstants.EZBAKE_APP_REGISTRATION_IMPL);
        if (impl != null) {
            try {
                LOGGER.info("Initializing registration service: {}", impl);
                Class<? extends EzbakeRegistrationService> clazz = Class.forName(impl)
                        .asSubclass(EzbakeRegistrationService.class);
                bind(EzbakeRegistrationService.class).to(clazz);
            } catch (Exception e) {
                LOGGER.error("Caught exception instantiating app registration service impl {}", impl, e);
                throw new RuntimeException("Unable to initialize the app registration service implementation", e);
            }
        } else {
            LOGGER.info("Initializing security handler with defualt registration service: {}",
                    FileBackedRegistrations.class.getSimpleName());
            bind(EzbakeRegistrationService.class).to(FileBackedRegistrations.class);
        }
    }
}
