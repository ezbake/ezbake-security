package ezbake.security.client.validation;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import ezbake.base.thrift.EzSecurityToken;
import ezbake.base.thrift.EzSecurityTokenException;
import ezbake.crypto.PKeyCrypto;
import ezbake.crypto.utils.EzSSL;
import ezbake.security.client.EzBakeSecurityClientConfigurationHelper;
import ezbake.security.common.core.EzSecurityTokenUtils;
import ezbake.security.common.core.TokenExpiredException;
import ezbakehelpers.ezconfigurationhelpers.application.EzBakeApplicationConfigurationHelper;

import java.io.IOException;
import java.util.Properties;

/**
 * Class that provides validation for EzSecurityTokens
 */
public class EzSecurityTokenValidator implements TokenValidator<EzSecurityToken> {

    private EzBakeApplicationConfigurationHelper applicationConfigurationHelper;
    private EzBakeSecurityClientConfigurationHelper securityConfigurationHelper;
    private Supplier<PKeyCrypto> crypto;

    public EzSecurityTokenValidator(final Properties configuration) {
        this.applicationConfigurationHelper = new EzBakeApplicationConfigurationHelper(configuration);
        this.securityConfigurationHelper = new EzBakeSecurityClientConfigurationHelper(configuration);
        this.crypto = Suppliers.memoize(new Supplier<PKeyCrypto>() {
            @Override
            public PKeyCrypto get() {
                try {
                    return EzSSL.getCrypto(configuration);
                } catch (IOException e) {
                    throw new RuntimeException("Unable to verify tokens without the proper RSA key configuration", e);
                }
            }
        });
    }

    @Override
    public void validateToken(EzSecurityToken token) throws EzSecurityTokenException, TokenExpiredException {
        if(securityConfigurationHelper.useMock()) {
            return;
        }
        EzSecurityTokenUtils.verifyReceivedToken(crypto.get(), token, applicationConfigurationHelper.getSecurityID());
    }

    /**
     * Validates a security token using a new token validator. This differs from the instance validateToken in that it
     * only throws an EzSecurityTokenException, catching the expired exception and rethrowing
     *
     * @param token a token to verify
     * @param configuration the configuration properties for the app
     * @throws EzSecurityTokenException
     */
    public static void validateToken(EzSecurityToken token, Properties configuration)
            throws EzSecurityTokenException {
        try {
            new EzSecurityTokenValidator(configuration).validateToken(token);
        } catch (TokenExpiredException e) {
            throw new EzSecurityTokenException(e.getMessage());
        }
    }
}
