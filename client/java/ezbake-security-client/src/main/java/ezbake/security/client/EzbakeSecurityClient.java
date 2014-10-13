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

package ezbake.security.client;

import com.google.common.base.Strings;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.Lists;
import com.google.inject.Guice;
import com.google.inject.Inject;

import ezbake.base.thrift.*;
import ezbake.common.properties.EzProperties;
import ezbake.crypto.PKeyCrypto;
import ezbake.crypto.utils.EzSSL;
import ezbake.security.client.provider.EzbakeTokenProvider;
import ezbake.security.client.validation.EzSecurityTokenValidator;
import ezbake.security.client.validation.TokenValidator;
import ezbake.security.common.core.EzSecurityClient;
import ezbake.security.common.core.EzSecurityTokenUtils;
import ezbake.security.common.core.SecurityID;
import ezbake.security.common.core.TokenExpiredException;
import ezbake.security.thrift.EzSecurity;

import ezbake.security.thrift.ezsecurityConstants;
import ezbakehelpers.ezconfigurationhelpers.application.EzBakeApplicationConfigurationHelper;
import org.apache.thrift.TException;
import ezbake.thrift.ThriftClientPool;
import org.apache.thrift.TSerializer;
import org.apache.thrift.protocol.TSimpleJSONProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;

import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.*;

/**
 * User: jhastings
 * Date: 10/10/13
 * Time: 2:16 PM
 */
@SuppressWarnings({"DuplicateThrows"})
public class EzbakeSecurityClient implements EzSecurityClient, Closeable {
    private static Logger log = LoggerFactory.getLogger(EzbakeSecurityClient.class);

    public static final String EFE_USER_HEADER = "ezb_verified_user_info";
    public static final String EFE_SIGNATURE_HEADER = "ezb_verified_signature";
    public static final String SESSION_TOKEN = "SESSION_TOKEN";

    private static long expiry = 10 * 60 * 1000; //millis

    private static Cache<String, EzSecurityToken> tokenCache = CacheBuilder.newBuilder()
            .maximumSize(1000).build();

    /**
     * This is to detect if we used the pool or not.  Since the supplier API does not have an accessor to test
     * if something has referenced it yet.  This is safe to do, because the only time we actually check it would be
     * in close, which would already cause indeterminate behavior if it was called at the same time another active
     * thread would be calling into a function that works on the pool anyways.  As the pool becomes in a bad state after
     * close is called.
     */
    private boolean poolCreated = false;
    /**
     * This here will create the pool once on first use.
     */
    private Supplier<ThriftClientPool> pool;

    private Supplier<PKeyCrypto> crypto;
    private boolean cryptoCreated = false;

    private EzProperties properties;
    private final EzBakeApplicationConfigurationHelper applicationConfiguration;
    private final EzBakeSecurityClientConfigurationHelper securityConfigurationHelper;
    private EzbakeTokenProvider tokenProvider;
    private TokenValidator<EzSecurityToken> tokenValidator;


    public EzbakeSecurityClient(Properties properties) {
        this(properties, null);
    }

    @Inject
    public EzbakeSecurityClient(final Properties properties, final ThriftClientPool clientPool) {

        try {
            pool = Suppliers.memoize(new Supplier<ThriftClientPool>() {
                @Override
                public ThriftClientPool get() {
                    poolCreated = true;
                    if (clientPool != null) {
                        return clientPool;
                    } else {
                        return new ThriftClientPool(properties);
                    }

                }
            });
        }
        catch(Exception e) {
            log.debug("Could Not Find Connection to the zookeeper");
        }

        crypto = Suppliers.memoize(new Supplier<PKeyCrypto>() {
            @Override
            public PKeyCrypto get() {
                cryptoCreated = true;
                try {
                    return EzSSL.getCrypto(properties);
                } catch (IOException e) {
                    throw new RuntimeException("Unable to sign or verify secure messages without the proper RSA keys", e);
                }
            }
        });

        this.properties = new EzProperties(properties, true);
        this.applicationConfiguration = new EzBakeApplicationConfigurationHelper(properties);
        this.securityConfigurationHelper = new EzBakeSecurityClientConfigurationHelper(properties);
        this.tokenValidator = new EzSecurityTokenValidator(properties);

        tokenProvider = Guice.createInjector(new EzbakeTokenProvider.Module(properties, pool, crypto))
                .getInstance(EzbakeTokenProvider.class);
    }
    
    @Override
    public void close() throws IOException {
        this.closePool();
    }

    public ThriftClientPool getThriftClientPool() {
        return pool.get();
    }

    public String getRegisteredSecurityId(String applicationServiceName) {
        return pool.get().getSecurityId(applicationServiceName);
    }

    public synchronized EzSecurity.Client getClient() throws TException {
        return this.pool.get().getClient(ezsecurityConstants.SERVICE_NAME, EzSecurity.Client.class);
    }

    public synchronized void returnClient(EzSecurity.Client client) {
        this.pool.get().returnToPool(client);
    }

    public synchronized void closePool() {
        if (poolCreated) {
            this.pool.get().close();
        }
    }

    private PKeyCrypto getCrypto() {
        return crypto.get();
    }



    /**
     * Ping the security service
     *
     * @return response received by security service
     * @throws TException on thrift exception
     */
    public boolean ping() throws TException {
        boolean ping = false;

        EzSecurity.Client client = getClient();
        try {
            ping = client.ping();
        } finally {
            returnClient(client);
        }

        return ping;
    }

    /**
     * Used to determine whether or not a user should be given access to Ezbake Administrator functionality
     *
     * @deprecated use {@link EzSecurityTokenWrapper#isEzAdmin()} instead
     *
     * @param token EzSecurity token to be evaluated
     * @return true if the user is an EzAdmin
     */
    @Deprecated
    public static boolean isEzAdmin(EzSecurityToken token) {
        return EzSecurityTokenUtils.isEzAdmin(token);
    }

    /**
     * Validate an EzSecurityToken received by anyone other than the security service. This should always be called
     * before trusting the information present in the received token.
     *
     * @param token received token
     * @throws EzSecurityTokenException if the token is invalid
     */
    public void validateReceivedToken(EzSecurityToken token) throws EzSecurityTokenException {
        try {
            tokenValidator.validateToken(token);
        } catch(TokenExpiredException e) {
            EzSecurityToken newToken = tokenProvider.refreshSecurityToken(token);

            // copy to overwrite values on the passed in token
            for (EzSecurityToken._Fields field : EzSecurityToken._Fields.values()) {
                token.setFieldValue(field, newToken.getFieldValue(field));
            }
        }
    }

    /**
     * Verify that the header DN and signature were issued by EzSecurity
     * @throws EzSecurityTokenException if the headers are missing or invalid
     */
    public void validateCurrentRequest() throws EzSecurityTokenException {
        ProxyPrincipal pp = requestPrincipalFromRequest();
        verifyProxyUserToken(pp.getProxyToken(), pp.getSignature());
    }

    public void verifyProxyUserToken(String token, String signature) throws EzSecurityTokenException {
        if (securityConfigurationHelper.useMock()) {
            return;
        }
        if (EzSecurityTokenUtils.verifyProxyUserToken(token, signature, getCrypto())) {
            ProxyUserToken put = EzSecurityTokenUtils.deserializeProxyUserToken(token);
            long currentTime = System.currentTimeMillis();
            if (put.getNotAfter() <= currentTime) {
                log.warn("Verification of User Principal expiration timestamp from headers failed {} < {}",
                        put.getNotAfter(), currentTime);
                throw new EzSecurityTokenException("Token from HTTP headers was expired");
            }
        } else {
            log.warn("Proxy header verification failed due to invalid signature");
            throw new EzSecurityTokenException("Unable to verify signature of user info from HTTP headers");
        }
    }

    public boolean verifyEzSecurityPrincipal(final EzSecurityPrincipal token) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        log.debug("Verifying EzSecurityDn for {}", token.getPrincipal());
        return System.currentTimeMillis() < token.getValidity().getNotAfter() && EzSecurityTokenUtils.verifyPrincipalSignature(token, getCrypto());
    }

    protected boolean verifyUserInfoResponse(final EzSecurityToken token) {
        if (securityConfigurationHelper.useMock()) {
            return true;
        }

        boolean valid =  EzSecurityTokenUtils.verifyTokenSignature(token, getCrypto());
        // check not expired
        if (token.getValidity().getNotAfter() <= System.currentTimeMillis()) {
            valid = false;
        }
        return valid;
    }

    /**
     * Make a best attempt to get the user DN from the OFE headers.
     *
     * The method will never return null. It will either successfully extract a
     * Security Principal or it will throw an EzSecurityTokenException. If in mock mode,
     * return a mock Principal
     *
     * @deprecated EFE headers no longer contain a valid EzSecurityPrincipal. Use
     * {@link ezbake.security.client.EzbakeSecurityClient#requestPrincipalFromRequest(javax.servlet.http.HttpServletRequest)} instead
     *
     * @param request HTTP request carrying the OFE headers
     * @return valid EzSecurityPrincipal if able to get one
     */
    @Deprecated
    public EzSecurityPrincipal clientDnFromRequest(HttpServletRequest request) throws EzSecurityTokenException {
        // Return user from configuration if in 'mock' mode
        if (securityConfigurationHelper.useMock()) {
            return new EzSecurityPrincipal(securityConfigurationHelper.getMockUser(),
                    new ValidityCaveats("EzSecurity", "", System.currentTimeMillis()+expiry, ""));
        }

        if (log.isTraceEnabled()) {
            Enumeration<String> headers = request.getHeaderNames();
            while (headers.hasMoreElements()) {
                String headerName = headers.nextElement();
                log.trace("Header: " + headerName + " = " + request.getHeader(headerName));
            }
        }

        String dnHeader = getHeaderValue(request, EFE_USER_HEADER);
        String dnSignature = getHeaderValue(request, EFE_SIGNATURE_HEADER);

        EzSecurityPrincipal dn = null;
        if (dnHeader != null && dnSignature != null) {
            verifyProxyUserToken(dnHeader, dnSignature);
            ProxyUserToken put = EzSecurityTokenUtils.deserializeProxyUserToken(dnHeader);
            dn = new EzSecurityPrincipal(
                    put.getX509().getSubject(),
                    new ValidityCaveats(
                            put.getIssuedBy(),
                            put.getIssuedTo(),
                            put.getNotAfter(),
                            dnSignature));

        }
        if (dn == null) {
            throw new EzSecurityTokenException("Unable to get user DN from HttpServletRequest");
        }

        return dn;
    }

    /**
     * Make a best attempt to get the user DN from the HTTP headers. This will use the RequestContextHolder to
     * get the HttpServletRequest. Requires that org.springframework.web.context.request.RequestContextListener be
     * registered in the deployment descriptor.
     *
     * @deprecated HTTP headers no longer contain a valid EzSecurityPrincipal. Use
     * {@link ezbake.security.client.EzbakeSecurityClient#requestPrincipalFromRequest()} instead
     *
     * @return valid EzSecurityPrincipal if able to get one, otherwise null. If in mock mode, return a mock principal
     */
    @Deprecated
    public EzSecurityPrincipal clientDnFromRequest() throws EzSecurityTokenException {
        // Return user from configuration if in 'mock' mode
        if (securityConfigurationHelper.useMock()) {
            return new EzSecurityPrincipal(securityConfigurationHelper.getMockUser(),
                    new ValidityCaveats("EzSecurity", "", System.currentTimeMillis()+expiry, ""));
        }

        ServletRequestAttributes reqAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (reqAttributes == null) {
            log.error("Unable to get request attributes. Make sure you have org.springframework.web.context.request.RequestContextListener registered in your web.xml");
            return null;
        }

        HttpServletRequest req = reqAttributes.getRequest();
        if (req == null) {
            log.error("Unable to get request from attributes");
            return null;
        }

        return clientDnFromRequest(req);
    }


    /**
     * Attempt to read the proxy princiapl from the HTTP headers. This will use the RequestContextHolder to
     * get the HttpServletRequest. Requires that org.springframework.web.context.request.RequestContextListener be
     * registered in the deployment descriptor.
     *
     * @return the proxy principal that was contained in the HTTP headers
     * @throws EzSecurityTokenException
     */
    public ProxyPrincipal requestPrincipalFromRequest() throws EzSecurityTokenException {
        // Return user from configuration if in 'mock' mode
        if (securityConfigurationHelper.useMock()) {
            return new ProxyPrincipal(generateMockProxyToken(securityConfigurationHelper.getMockUser()), "");
        }

        ServletRequestAttributes reqAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (reqAttributes == null) {
            log.error("Unable to get request attributes. Make sure you have " +
                    "org.springframework.web.context.request.RequestContextListener registered in your web.xml");
            throw new EzSecurityTokenException("Unable to get request attributes. Make sure you have " +
                    "org.springframework.web.context.request.RequestContextListener registered in your web.xml?");
        }

        HttpServletRequest req = reqAttributes.getRequest();
        if (req == null) {
            log.error("Unable to get request from attributes");
            throw new EzSecurityTokenException("Unable to get HttpServletRequest from ServletRequestAttributes");
        }

        return requestPrincipalFromRequest(req);
    }

    /**
     * Attempt to read the proxy princiapl from the HTTP headers.
     *
     * @param request the servlet request for the current request
     * @return the proxy principal that was contained in the HTTP headers
     * @throws EzSecurityTokenException
     */
    public ProxyPrincipal requestPrincipalFromRequest(HttpServletRequest request) throws EzSecurityTokenException {
        if (log.isTraceEnabled()) {
            Enumeration<String> headers = request.getHeaderNames();
            while (headers.hasMoreElements()) {
                String headerName = headers.nextElement();
                log.trace("Header: " + headerName + " = " + request.getHeader(headerName));
            }
        }

        // Convert the headers into a map
        Map<String, List<String>> headers = new HashMap<>();
        for (String headerName : Collections.list(request.getHeaderNames())) {
            if (headers.containsKey(headerName)) {
                headers.get(headerName).add(request.getHeader(headerName));
            } else {
                headers.put(headerName.toUpperCase(), Lists.newArrayList(request.getHeader(headerName)));
            }
        }

        return requestPrincipalFromRequest(headers);
    }

    /**
     * Look up the headers for the proxy principal in the passed in map of headers
     *
     * @param headers map of headers
     * @return a proxy principal if one was contained in the headers
     * @throws EzSecurityTokenException
     */
    public ProxyPrincipal requestPrincipalFromRequest(Map<String, List<String>> headers) throws EzSecurityTokenException {
        log.debug("Request Principal From Request\nIn Mock: {}", securityConfigurationHelper.useMock());
 
        String dnHeader = getHeaderValue(headers, EFE_USER_HEADER);
        String dnSignature = getHeaderValue(headers, EFE_SIGNATURE_HEADER);

        if (securityConfigurationHelper.useMock() && (dnHeader == null || dnHeader.isEmpty())) {
            return new ProxyPrincipal(generateMockProxyToken(securityConfigurationHelper.getMockUser()), "");
        }
        
        
        ProxyPrincipal principal;
        if (dnHeader != null && dnSignature != null) {
            log.debug("Found Header Value " + dnHeader);
            verifyProxyUserToken(dnHeader, dnSignature);
            principal = new ProxyPrincipal(dnHeader, dnSignature);
        } else {
            throw new EzSecurityTokenException("Unable to get user DN from HttpServletRequest");
        }

        return principal;
    }

    private String getHeaderValue(HttpServletRequest request, String header) {
        String value = request.getHeader(header);
        if (value == null) {
            //Try to get the header the rails way
            value = request.getHeader("HTTP_" + header.toUpperCase());
        }
        log.trace("Tried to get {} {}", header, value);
        return value;
    }

    private String getHeaderValue(Map<String, List<String>> headers, String headerName) {
        String needle = headerName.toUpperCase();

        // Hope that it's in the map in the correct case
        List<String> values = headers.get(needle);

        // Maybe wrong case, search all of the entries
        if (values == null || values.size() == 0) {
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                if (entry.getKey().toUpperCase().equals(needle)) {
                    values = entry.getValue();
                    break;
                }
            }
        }

        // Still nothing, try the Rails way with upper case names
        if (values == null || values.size() == 0) {
            needle = "HTTP_" + headerName.toUpperCase();
            values = headers.get(needle);
        }

        // Last try, Rails way searching all of the entries
        if (values == null || values.size() == 0) {
            needle = "HTTP_" + headerName.toUpperCase();
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                if (entry.getKey().toUpperCase().equals(needle)) {
                    values = entry.getValue();
                    break;
                }
            }
        }

        String value = null;
        if (values != null) {
            value = values.get(0);
        }
        log.trace("Tried to get {} {}", headerName, value);
        return value;
    }

    private String generateMockProxyToken(String userSubject) throws EzSecurityTokenException {
        ProxyUserToken token = new ProxyUserToken(new X509Info(userSubject), "EzSecurity", "",
                System.currentTimeMillis()+expiry);
        try {
            return new String(new TSerializer(new TSimpleJSONProtocol.Factory()).serialize(token), StandardCharsets.UTF_8);
        } catch (TException e) {
            throw new EzSecurityTokenException("Unable to generate a mock user principal: "+e.getMessage());
        }
    }

    /**
     * Fetch a token for the currently proxied user. The proxied user info will be taken from the request headers
     *
     * @return a USER token
     * @throws EzSecurityTokenException
     */
    public EzSecurityTokenWrapper fetchTokenForProxiedUser() throws EzSecurityTokenException {
        return fetchTokenForProxiedUser(applicationConfiguration.getSecurityID());
    }

    /**
     * Fetch a token for the currently proxied user. The proxied user info will be taken from the request headers
     *
     * @param refreshToken whether or not to check the cache for the token
     * @return a USER token
     * @throws EzSecurityTokenException
     */
    public EzSecurityTokenWrapper fetchTokenForProxiedUser(boolean refreshToken) throws EzSecurityTokenException {
        return fetchTokenForProxiedUser(applicationConfiguration.getSecurityID(), refreshToken);
    }

    /**
     * Fetch a token for the currently proxied user. The proxied user info will be taken from the request headers
     *
     * @param targetId the application the token should be issuedFor
     * @return a USER token
     * @throws EzSecurityTokenException
     */
    public EzSecurityTokenWrapper fetchTokenForProxiedUser(String targetId) throws EzSecurityTokenException {
        return fetchTokenForProxiedUser(requestPrincipalFromRequest(), targetId);
    }

    /**
     * Fetch a token for the currently proxied user. The proxied user info will be taken from the request headers
     *
     * @param targetId the application the token should be issuedFor
     * @return a USER token
     * @throws EzSecurityTokenException
     */
    public EzSecurityTokenWrapper fetchTokenForProxiedUser(String targetId, boolean refreshToken) throws EzSecurityTokenException {
        return fetchTokenForProxiedUser(requestPrincipalFromRequest(), targetId, refreshToken);
    }

    /**
     * Fetch a token for the currently proxied user
     *
     * @param principal the principal of the proxied user
     * @param targetID the application the token should be issuedFor
     * @return a USER token
     * @throws EzSecurityTokenException
     */
    public EzSecurityTokenWrapper fetchTokenForProxiedUser(ProxyPrincipal principal, String targetID) throws EzSecurityTokenException {
        return fetchTokenForProxiedUser(principal, targetID, false);
    }

    /**
     * Fetch a token for the currently proxied user
     *
     * @param principal the principal of the proxied user
     * @param targetID the application the token should be issuedFor
     * @param refreshToken whether or not to check the cache for the token
     * @return a USER token
     * @throws EzSecurityTokenException
     */
    public EzSecurityTokenWrapper fetchTokenForProxiedUser(ProxyPrincipal principal, String targetID,
                                                           boolean refreshToken)
            throws EzSecurityTokenException {
        String targetSecurityId = getTargetAppSecurityId(targetID);

        // First construct the TokenRequest Key
        TokenRequest userRequest = new TokenRequest(applicationConfiguration.getSecurityID(),
                System.currentTimeMillis(), TokenType.USER);
        userRequest.setProxyPrincipal(principal);
        userRequest.setTargetSecurityId(targetSecurityId);

        ProxyUserToken proxyToken = EzSecurityTokenUtils.deserializeProxyUserToken(principal.getProxyToken());
        String cacheKey = userRequest.getType().toString()+proxyToken.getX509().getSubject()+userRequest.getTargetSecurityId();
        EzSecurityToken token = getTokenFromCache(cacheKey, refreshToken);
        if (token != null) {
            return new EzSecurityTokenWrapper(token);
        }

        //userRequest.get
        token = tokenProvider.getSecurityToken(userRequest);

        // Only put it in the cache after verification
        tokenCache.put(cacheKey, token);

        return new EzSecurityTokenWrapper(token);
    }

    /**
     * Fetch a token for the currently proxied user. The proxied user info will be taken from a map
     *
     * @return a USER token
     * @throws EzSecurityTokenException
     */
    public EzSecurityTokenWrapper fetchTokenForProxiedUser(Map<String, String[]> headers) throws EzSecurityTokenException {
        Map<String, List<String>> headerList = new HashMap<>();
        for (String key : headers.keySet()) {
            headerList.put(key.toUpperCase(),Arrays.asList(headers.get(key)));
        }
        return fetchTokenForProxiedUser(requestPrincipalFromRequest(headerList),applicationConfiguration.getSecurityID());
    }

    /**
     * Fetch an EzSecurityToken for the app running this client. It will also be issued for the current app
     *
     * @return an APP for the token
     * @throws EzSecurityTokenException
     */
    public EzSecurityTokenWrapper fetchAppToken() throws EzSecurityTokenException {
        return this.fetchAppToken(applicationConfiguration.getSecurityID());
    }

    /**
     * Fetch an EzSecurityToken for the app running this client. It will also be issued for the current app
     *
     * @return an APP for the token
     * @throws EzSecurityTokenException
     */
    public EzSecurityTokenWrapper fetchAppToken(boolean refreshToken) throws EzSecurityTokenException {
        return this.fetchAppToken(applicationConfiguration.getSecurityID(), refreshToken);
    }

    /**
     * Fetch an EzSecurityToken for the app running this client, that will be issued for the target application.
     *
     * @param targetID security id of the app it should be issued for
     * @return an APP for the token
     * @throws EzSecurityTokenException
     */
    public EzSecurityTokenWrapper fetchAppToken(String targetID) throws EzSecurityTokenException {
        return fetchAppToken(targetID, false);
    }

    /**
     * Fetch an EzSecurityToken for the app running this client, that will be issued for the target application.
     *
     * @param targetID security id of the app it should be issued for
     * @param refreshToken whether or not to check the cache for the token
     * @return an APP for the token
     * @throws EzSecurityTokenException
     */
    public EzSecurityTokenWrapper fetchAppToken(String targetID, boolean refreshToken) throws EzSecurityTokenException {
        String targetSecurityId = getTargetAppSecurityId(targetID);
        
        // First construct the token request key
        TokenRequest request = new TokenRequest(applicationConfiguration.getSecurityID(), System.currentTimeMillis(),
                TokenType.APP);
        request.setTargetSecurityId(targetSecurityId);

        String cacheKey = request.getType().toString()+targetSecurityId;
        EzSecurityToken info = getTokenFromCache(cacheKey, refreshToken);
        if (info != null) {
            return new EzSecurityTokenWrapper(info);
        }

        info = tokenProvider.getSecurityToken(request);
        tokenCache.put(cacheKey, info);

        return new EzSecurityTokenWrapper(info);
    }

    /**
     * Fetch a token from EzSecurity that will be derived from a token that was received previously. This will retain
     * the information about the subject, but can be issuedFor other target applications
     *
     * @param token a token issued by EzSecurity
     * @param targetID the issuedFor application
     * @return a derived EzSecurity token
     * @throws EzSecurityTokenException
     */
    public EzSecurityTokenWrapper fetchDerivedTokenForApp(EzSecurityToken token, String targetID) throws EzSecurityTokenException {
        return fetchDerivedTokenForApp(token, targetID, false);
    }

    /**
     * Fetch a token from EzSecurity that will be derived from a token that was received previously. This will retain
     * the information about the subject, but can be issuedFor other target applications
     *
     * @param token a token issued by EzSecurity
     * @param targetID the issuedFor application
     * @param refreshToken whether or not to check the cache for the token
     * @return a derived EzSecurity token
     * @throws EzSecurityTokenException
     */
    public EzSecurityTokenWrapper fetchDerivedTokenForApp(EzSecurityToken token, String targetID, boolean refreshToken)
            throws EzSecurityTokenException {
        String targetSecurityId = getTargetAppSecurityId(targetID);
        TokenRequest tokenRequest = new TokenRequest(applicationConfiguration.getSecurityID(), System.currentTimeMillis(), token.getType());
        tokenRequest.setTokenPrincipal(token);
        tokenRequest.setTargetSecurityId(targetSecurityId);

        String cacheKey = tokenRequest.getType().toString()+token.getTokenPrincipal().getRequestChain()+targetSecurityId;
        EzSecurityToken derivedToken = getTokenFromCache(cacheKey, refreshToken);
        if (derivedToken != null) {
            return new EzSecurityTokenWrapper(derivedToken);
        }

        derivedToken = tokenProvider.getSecurityToken(tokenRequest);
        tokenCache.put(cacheKey, derivedToken);

        return new EzSecurityTokenWrapper(derivedToken);
    }

    /**
     * Get a token from the local cache. If no token is present, return null. If refresh is true just return null.
     * @param key the cache key
     * @param refresh whether or not to actually look in the cache
     * @return a token from the cache or null
     */
    private EzSecurityToken getTokenFromCache(String key, boolean refresh) {
        if (!refresh) {
            EzSecurityToken token = tokenCache.getIfPresent(key);
            if (token != null) {
                if (verifyUserInfoResponse(token)) {
                    log.debug("Returning token from cache. Expires: {}", token.getValidity().getNotAfter());
                    return token;
                } else {
                    log.debug("Token has expired or was invalid. Invalidating cache object");
                    tokenCache.invalidate(key);
                }
            }
        }
        return null;
    }

    /**
     * Returns the security id of the specified targetApp. If the targetApp is already in the format of a security id,
     * then no lookup is performed, and the passed in value is returned
     *
     * @param targetApp app/common service name of the target application
     * @return the security id of the passed app/common service, or the targetApp if already a security id
     */
    protected String getTargetAppSecurityId(String targetApp) {
        String securityId;
        if (!securityConfigurationHelper.useMock()) {
            securityId = targetApp;
            if (Strings.isNullOrEmpty(securityId)) {
                securityId = applicationConfiguration.getSecurityID();
            } else if (!SecurityID.isSecurityId(securityId)) {
                // Look up the security id in service discovery
                securityId = pool.get().getSecurityId(targetApp);
            }
        } else {
            securityId = targetApp;
            if (Strings.isNullOrEmpty(securityId)) {
                securityId = securityConfigurationHelper.getMockTarget();
            }
        }
        return securityId;
    }

}
