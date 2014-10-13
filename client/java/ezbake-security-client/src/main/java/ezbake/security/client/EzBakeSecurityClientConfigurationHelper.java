package ezbake.security.client;

import ezbake.common.properties.EzProperties;

import java.util.Properties;

/**
 * User: jhastings
 * Date: 10/13/14
 * Time: 11:19 AM
 */
public class EzBakeSecurityClientConfigurationHelper {
    public static final String USE_MOCK_KEY = "ezbake.security.client.use.mock";
    public static final String MOCK_USER_KEY = "ezbake.security.client.mock.user.dn";
    public static final String MOCK_TARGET_ID_KEY = "ezbake.security.client.mock.target.id";

    private EzProperties properties;

    public EzBakeSecurityClientConfigurationHelper(Properties configuration) {
        properties = new EzProperties(configuration, true);
    }

    /**
     * Gets the mock mode from EzConfiguration
     * @return true if this client is in mock
     */
    public boolean useMock() {
        return properties.getBoolean(USE_MOCK_KEY, false);
    }

    /**
     * Get the mock user ID from the EzConfiguration
     * @return the mock user ID
     */
    public String getMockUser() {
        return properties.getProperty(MOCK_USER_KEY, "");
    }

    public String getMockUser(String defaultUser) {
        return properties.getProperty(MOCK_USER_KEY, defaultUser);
    }

    /**
     * Get the mock target SecurityID from EzConfiguration
     * @return the mock target SecurityID
     */
    public String getMockTarget() {
        return properties.getProperty(MOCK_TARGET_ID_KEY, null);
    }
}
