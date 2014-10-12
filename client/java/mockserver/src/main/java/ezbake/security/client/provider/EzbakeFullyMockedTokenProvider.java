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

package ezbake.security.client.provider;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Properties;

import com.google.common.base.Supplier;
import com.google.inject.Inject;
import ezbake.base.thrift.EzSecurityTokenException;
import ezbake.configuration.EzConfigurationLoaderException;
import ezbake.configuration.constants.EzBakePropertyConstants;
import ezbake.crypto.PKeyCrypto;
import ezbake.crypto.PKeyCryptoException;
import ezbake.crypto.utils.CryptoUtil;
import ezbake.crypto.utils.EzSSL;
import ezbake.security.impl.ua.FileUAService;
import ezbake.security.thrift.AppNotRegisteredException;
import ezbake.security.ua.UAModule;
import org.apache.thrift.TException;

import ezbake.base.thrift.EzSecurityToken;
import ezbake.base.thrift.TokenRequest;
import ezbake.security.common.core.EzSecurityTokenUtils;
import ezbake.security.service.processor.EzSecurityHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EzbakeFullyMockedTokenProvider implements EzbakeTokenProvider {
    private static final Logger log = LoggerFactory.getLogger(EzbakeFullyMockedTokenProvider.class);
    private Supplier<PKeyCrypto> crypto;
    private EzSecurityHandler securityHandler;

    @Inject
    public EzbakeFullyMockedTokenProvider(Properties properties, Supplier<PKeyCrypto> crypto) throws UnrecoverableKeyException, KeyManagementException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, EzConfigurationLoaderException {
        if (!properties.containsKey(UAModule.UA_SERVICE_IMPL)) {
            properties.setProperty(UAModule.UA_SERVICE_IMPL, FileUAService.class.getCanonicalName());
        }
        properties.setProperty(EzBakePropertyConstants.EZBAKE_SECURITY_SERVICE_MOCK_SERVER, Boolean.TRUE.toString());
        securityHandler = EzSecurityHandler.getHandler(properties);
        this.crypto = crypto;
    }
    
    private String signRequest(final TokenRequest request) {
        String signed = "";

        try {
            signed = CryptoUtil.encode(crypto.get().sign(EzSecurityTokenUtils.serializeTokenRequest(request)));
        } catch (PKeyCryptoException|IOException e) {
            log.error("Didn't sign token request: {}", e.getMessage());
        }

        return signed;
    }
    
    public EzSecurityToken getSecurityToken(TokenRequest tokenRequest) throws EzSecurityTokenException {
        try {
            return securityHandler.requestToken(tokenRequest, signRequest(tokenRequest));
        } catch (AppNotRegisteredException e) {
            log.error("Application {} is not registered with EzSecurity", tokenRequest.getSecurityId(), e);
            throw new EzSecurityTokenException("Application not registered " + e.getMessage());
        } catch (EzSecurityTokenException e) {
            throw e;
        } catch (TException e) {
            log.error("Unexpected thrift exception getting security token: {}", e.getMessage());
            throw new EzSecurityTokenException("TException getting security token: "+e.getMessage());
        }
    }

    @Override
    public EzSecurityToken refreshSecurityToken(EzSecurityToken token) throws EzSecurityTokenException {
        return token;
    }

}
