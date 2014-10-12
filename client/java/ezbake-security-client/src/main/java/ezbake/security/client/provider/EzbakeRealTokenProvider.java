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
import java.util.Properties;

import com.google.inject.Inject;
import ezbake.crypto.PKeyCrypto;
import ezbake.crypto.PKeyCryptoException;
import ezbake.crypto.utils.CryptoUtil;
import ezbake.security.client.EzSecurityTokenWrapper;
import ezbake.security.thrift.AppNotRegisteredException;
import ezbake.security.thrift.ezsecurityConstants;
import ezbakehelpers.ezconfigurationhelpers.application.EzBakeApplicationConfigurationHelper;
import org.apache.thrift.TException;
import ezbake.thrift.ThriftClientPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Supplier;

import ezbake.base.thrift.EzSecurityToken;
import ezbake.base.thrift.EzSecurityTokenException;
import ezbake.base.thrift.TokenRequest;
import ezbake.security.common.core.EzSecurityTokenUtils;
import ezbake.security.thrift.EzSecurity;


public class EzbakeRealTokenProvider implements EzbakeTokenProvider {
    private Logger log = LoggerFactory.getLogger(EzbakeRealTokenProvider.class);
    
    /**
     * This here will create the pool once on first use.
     */
    protected Supplier<ThriftClientPool> pool;
    protected Supplier<PKeyCrypto> crypto;
    protected String securityId;

    @Inject
    public EzbakeRealTokenProvider(Properties properties, Supplier<ThriftClientPool> clientPool, Supplier<PKeyCrypto> crypto) {
        this.pool = clientPool;
        this.crypto = crypto;
        securityId = new EzBakeApplicationConfigurationHelper(properties).getSecurityID();
    }
    
    public EzSecurityToken getSecurityToken(TokenRequest tokenRequest) throws EzSecurityTokenException {
        EzSecurityToken token = null;
        EzSecurity.Client client = null;

        try {
            client = pool.get().getClient(ezsecurityConstants.SERVICE_NAME, EzSecurity.Client.class);
            token = client.requestToken(tokenRequest, signRequest(tokenRequest));
            verifyUserInfoResponse(token);
        } catch (AppNotRegisteredException e) {
            log.error("Application {} is not registered with EzSecurity", securityId, e);
            throw new EzSecurityTokenException("Application not registered " + e.getMessage());
        } catch (EzSecurityTokenException e) {
            throw e;
        } catch (TException e) {
            log.error("Unexpected thrift exception getting security token: {}", e.getMessage());
            throw new EzSecurityTokenException("TException getting security token: "+e.getMessage());
        }
        finally {
            pool.get().returnToPool(client);
        }

        return token;
    }

    @Override
    public EzSecurityToken refreshSecurityToken(EzSecurityToken token) throws EzSecurityTokenException {
        EzSecurityToken refreshedToken;
        EzSecurity.Client client = null;
        try {
            TokenRequest request = new TokenRequest(securityId,
                    System.currentTimeMillis(), token.getType());
            request.setTokenPrincipal(token);

            client = pool.get().getClient(ezsecurityConstants.SERVICE_NAME, EzSecurity.Client.class);
            refreshedToken = client.refreshToken(request, signRequest(request));
        } catch (AppNotRegisteredException e) {
            log.error("Application {} is not registered with EzSecurity", securityId, e);
            throw new EzSecurityTokenException("Application not registered " + e.getMessage());
        } catch (EzSecurityTokenException e) {
            throw e;
        } catch (TException e) {
            log.error("Unexpected thrift exception getting security token: {}", e.getMessage());
            throw new EzSecurityTokenException("TException getting security token: "+e.getMessage());
        } finally {
            if (client != null) {
                pool.get().returnToPool(client);
            }
        }

        return new EzSecurityTokenWrapper(refreshedToken);
    }

    protected String signRequest(final TokenRequest request) throws EzSecurityTokenException {
        String signed;

        try {
            signed = CryptoUtil.encode(crypto.get().sign(EzSecurityTokenUtils.serializeTokenRequest(request)));
        } catch (PKeyCryptoException|IOException e) {
            throw new EzSecurityTokenException("Unable to sign token request: " + e.getMessage());
        }

        return signed;
    }
    
    protected void verifyUserInfoResponse(final EzSecurityToken token) throws EzSecurityTokenException {
        // Check signature
        if (!EzSecurityTokenUtils.verifyTokenSignature(token, crypto.get())) {
            throw new EzSecurityTokenException("EzSecurityToken verification failed. Reason: invalid signature");
        }
        // check not expired
        long now = System.currentTimeMillis();
        if (token.getValidity().getNotAfter() < now) {
            log.info("Security Token verification failed. Reason: expired {} < {}", token.getValidity().getNotAfter(), now);
            throw new EzSecurityTokenException("EzSecurityToken verification failed. Reason: expired "+
                    token.getValidity().getNotAfter()+ " < " + now);
        }
    }
}
