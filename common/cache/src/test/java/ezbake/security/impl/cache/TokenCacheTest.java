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

package ezbake.security.impl.cache;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import ezbake.base.thrift.*;
import org.junit.Test;

public class TokenCacheTest {

    private static String testDn = "CN=Gary Drocella";
    private static String testSecurityId = "securityId";

    @Test
    public void test1() {
        TokenCache<TokenRequest, EzSecurityToken> tokenCache = new TokenCache<TokenRequest,EzSecurityToken>(10000);

        EzSecurityPrincipal principal = new EzSecurityPrincipal();
        principal.setPrincipal(testDn);
        principal.setValidity(new ValidityCaveats("EzSecurity", "", 0, ""));

        TokenRequest userRequest = new TokenRequest(testSecurityId, 0, TokenType.USER);
        userRequest.setPrincipal(principal);

    
        EzSecurityToken ezSec = getTestEzSecurityToken(testDn);
        
        tokenCache.put(userRequest, ezSec);
        
        EzSecurityToken lookup = tokenCache.get(userRequest, Object.class);
        
        assertTrue(lookup != null);
        assertTrue(lookup.getTokenPrincipal().getPrincipal().equals(testDn));
    }

    @Test
    public void test2() {
        TokenCache<TokenRequest, EzSecurityToken> tokenCache = new TokenCache<TokenRequest, EzSecurityToken>(10000);

        EzSecurityPrincipal principal = new EzSecurityPrincipal();
        principal.setPrincipal(testDn);
        principal.setValidity(new ValidityCaveats("EzSecurity", "", 0, ""));

        TokenRequest userRequest = new TokenRequest(testSecurityId, 0, TokenType.USER);
        userRequest.setPrincipal(principal);

        EzSecurityToken ezTok = getTestEzSecurityToken(testDn);
        tokenCache.put(userRequest, ezTok);

        EzSecurityToken ezTok2 = getTestEzSecurityToken("CN=Common Name,O=42six");

        TokenRequest userRequest2 = new TokenRequest("Different Security Id", 0, TokenType.USER);
        userRequest2.setPrincipal(principal);

        tokenCache.put(userRequest, ezTok);
        tokenCache.put(userRequest2, ezTok2);

        EzSecurityToken tok = tokenCache.get(userRequest, Object.class);

        assertTrue(tok != null);
        assertTrue(tok.getTokenPrincipal().getPrincipal().equals(testDn));


    }

    public EzSecurityToken getTestEzSecurityToken(String dn) {
        EzSecurityToken ezToken = new EzSecurityToken();
        ezToken.setValidity(new ValidityCaveats("EzSecurity", "", 0, ""));

        EzSecurityPrincipal principal = new EzSecurityPrincipal();
        principal.setPrincipal(dn);
        ezToken.setTokenPrincipal(principal);
     

        return ezToken;
    }
}
