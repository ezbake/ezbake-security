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

import com.google.common.collect.Lists;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.google.inject.Inject;
import ezbake.security.persistence.model.AppPersistenceModel;
import ezbake.security.util.FileWatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Paths;
import java.util.*;

/**
 * User: jhastings
 * Date: 10/7/13
 * Time: 4:07 PM
 */
public class FileBackedRegistrations implements EzbakeRegistrationService, FileWatcher.FileWatchUpdater {
    private static final Logger log = LoggerFactory.getLogger(FileBackedRegistrations.class);
    public static final String REGISTRATION_FILE = FileBackedRegistrations.class.getSimpleName()+".json";
    public static final String REGISTRATION_FILE_PATH = "ezbake.security.service.registration.file";

    private Properties ezProperties;
    private FileWatcher watchThread;
    private Map<String, FileBackedRegistration> registrationMap;

    @Inject
    public FileBackedRegistrations(Properties properties) {
        ezProperties = properties;
        String registrationFileName = ezProperties.getProperty(REGISTRATION_FILE_PATH, REGISTRATION_FILE);

        try {
            FileInputStream initialRegistrationIn = new FileInputStream(new File(registrationFileName));
            registrationMap = loadJSON(initialRegistrationIn);
        } catch (FileNotFoundException e) {
            // Initially, try reading from the root of the classpath
            log.debug("Trying {}", "/"+REGISTRATION_FILE);
            InputStream classpathInputStream = FileBackedRegistrations.class.getResourceAsStream("/"+REGISTRATION_FILE);
            if (classpathInputStream != null) {
                registrationMap = loadJSON(classpathInputStream);
            } else {
                log.info("Registrations file not found at start-up. Polling will continue watching for file: {}",
                        registrationFileName);
            }
        }

        // Start the file watching daemon thread
        watchThread = new FileWatcher(Paths.get(registrationFileName), this);
        new Thread(watchThread).start();
    }

    @Override
    public AppInstance getClient(String appName) {
        AppInstance reg = null;
        FileBackedRegistration fbreg = registrationMap.get(appName);
        if (fbreg != null) {
            AppPersistenceModel app = new AppPersistenceModel();
            app.setAppName(fbreg.getSecurityId());
            app.setVisibilityLevel(fbreg.getLevel());
            app.setVisibility(Lists.newArrayList(fbreg.getAuthorizations()));
            app.setCommunityAuthorizations(Lists.newArrayList(fbreg.getCommunityAuthorizations()));
            app.setPublicKey(fbreg.getPublicKey());
            app.setId(fbreg.getSecurityId());
            app.setAppDn(fbreg.getAppDn());
            reg = new AppInstance(app);
        }
        return reg;
    }

    public static Map<String, FileBackedRegistration> loadJSON(InputStream is) {
        Map<String, FileBackedRegistration> loaded = Collections.emptyMap();

        List<FileBackedRegistration> regs = new Gson().fromJson(
                new BufferedReader(new InputStreamReader(is)),
                new TypeToken<List<FileBackedRegistration>>(){}.getType());

        if (regs != null) {
            loaded = new HashMap<>();
            for (FileBackedRegistration registration : regs) {
                loaded.put(registration.getSecurityId(), registration);
            }
        }

        return loaded;
    }

    @Override
    public boolean loadUpdate(InputStream is) {
        if (is == null) {
            return true;
        }
        registrationMap = loadJSON(is);
        return true;
    }

    @Override
    public void close() throws IOException {
        if (this.watchThread != null) {
            this.watchThread.stopWatching();
        }
    }
}
