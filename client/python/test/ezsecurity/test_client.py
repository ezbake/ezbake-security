#   Copyright (C) 2013-2014 Computer Sciences Corporation
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

# -*- coding: utf-8 -*-
"""
Created on Tue Apr 15 10:22:14 2014

@author: jhastings
"""
import nose.tools as nt
import time
import logging
logging.basicConfig(level=logging.DEBUG)
import thrift.TSerialization as tser

from ezconfiguration.EZConfiguration import EZConfiguration
import ezconfiguration.helpers as EzC
from ezbakeBaseTypes.ttypes import TokenRequest, EzSecurityToken

import ezsecurity.client
from ezsecurity.util import TokenCache
from ezsecurity.client import EzSecurityClient

DN = "User Id"

class testEzSecurityClientAsEFE(object):
    def __init__(self):
        self.ezconf = EZConfiguration()
        self.ezconf.set("ezbake.security.ssl.dir", "test/certs/efe")
        self.ezconf.set("ezbake.security.app.id", "EFE")

    def setUp(self):
        self.client = EzSecurityClient(self.ezconf)

    def test_user_dn(self):
        dn = self.client._user_dn(DN)
        nt.assert_true(self.client.validateSignedDn(dn.DN, dn.signature))

class testEzSecurityClient(object):
    def __init__(self):
        self.ezconf = EZConfiguration()
        self.ezconf.set("ezbake.security.ssl.dir", "test/certs/client")
        self.ezconf.set("ezbake.security.app.id", "SecurityClientTest")

    def setUp(self):
        self.client = EzSecurityClient(self.ezconf)

    def testPing(self):
        nt.assert_equal(True, self.client.ping())

    def test_user_info(self):
        token = self.client.user_info(DN, "")

        nt.assert_equal(self.ezconf.get("ezbake.security.app.id"),
                        token.validity.issuedTo)
        nt.assert_equal(self.ezconf.get("ezbake.security.app.id"),
                        token.validity.issuedFor)
        nt.assert_equal(DN, token.tokenPrincipal.principal)
        nt.assert_list_equal(['A', 'B', 'C'], token.authorizations.formalAuthorizations)
        nt.assert_dict_equal(dict([('EzBake', ['Core']),
            ('Project', ['Test', 'Test2']),
            ('Nothing', ['groups', 'group2'])]), token.externalProjectGroups)
        nt.assert_equal("EzBake", token.organization)
        nt.assert_equal("USA", token.citizenship)
        nt.assert_equal("low", token.visibilityLevel)
        nt.assert_equal("shared", token.externalCommunities[0].communityType)
        nt.assert_equal("EzBake", token.externalCommunities[0].organization)
        nt.assert_list_equal(['TopicA'], token.externalCommunities[0].topics)
        nt.assert_list_equal(['Region1'], token.externalCommunities[0].regions)
        nt.assert_list_equal([], token.externalCommunities[0].groups)

    def test_app_info(self):
        token = self.client.fetch_app_token('SecurityClientTest')
        nt.assert_equal(self.ezconf.get("ezbake.security.app.id"),
                        token.validity.issuedTo)
        nt.assert_is_none(token.validity.issuedFor)
        nt.assert_list_equal(
            sorted(["A", "B", "C", "EzBake"]),
            token.authorizations.formalAuthorizations)
        nt.assert_equal("low", token.visibilityLevel)

    def test_app_info_with_target(self):
        token = self.client.fetch_app_token('SecurityClientTest', 'testapp')
        nt.assert_equal(self.ezconf.get("ezbake.security.app.id"),
                        token.validity.issuedTo)
        nt.assert_equal('testapp', token.validity.issuedFor)
        nt.assert_list_equal(
            sorted(["A", "B", "C", "EzBake"]),
            token.authorizations.formalAuthorizations)
        nt.assert_equal("low", token.visibilityLevel)

    def testBuildRequest(self):
        request = self.client.build_request(DN, "")
        nt.assert_equal(DN, request.distinguishedName.DN)
        nt.assert_equal(EzC.ApplicationConfiguration(self.ezconf).getSecurityID(), request.securityId)
        nt.assert_is_instance(request, TokenRequest)

    def test_validate_received_token(self):
        token = self.client.user_info(DN, "", "SecurityClientTest")
        nt.assert_true(self.client.validateReceivedToken(token))

        b = tser.serialize(token)
        token = EzSecurityToken()
        tser.deserialize(token, b)
        nt.assert_true(self.client.validateReceivedToken(token))

class testEzSecurityClientCache(object):
    def __init__(self):
        self.ezconf = EZConfiguration()
        self.ezconf.set("ezbake.security.ssl.dir", "test/certs/client")
        self.ezconf.set("ezbake.security.app.id", "SecurityClientTest")

    def setUp(self):
        self.client = EzSecurityClient(self.ezconf)
        EzSecurityClient.user_cache = TokenCache(2*60)

    def tearDown(self):
        EzSecurityClient.user_cache.clear()

    def test_cache_no_target(self):
        t1 = self.client.user_info(DN, "")
        t2 = self.client.user_info(DN, "")
        nt.assert_equal(t1, t2)

    def test_cache_same_target(self):
        t1 = self.client.user_info(DN, "", "SecurityClientTest")
        t2 = self.client.user_info(DN, "", "SecurityClientTest")
        nt.assert_equal(t1, t2)

    def test_cache_diff_target(self):
        t1 = self.client.user_info(DN, "", "SecurityClientTest")
        t2 = self.client.user_info(DN, "", "NotSecurityClientTest")
        nt.assert_not_equal(t1, t2)

    def test_cache_expire(self):
        EzSecurityClient.user_cache = TokenCache(0.5)
        t1 = self.client.user_info(DN, "", "SecurityClientTest")
        time.sleep(0.6)
        t2 = self.client.user_info(DN, "", "SecurityClientTest")
        nt.assert_not_equal(t1, t2)

    def test_appcache_no_target(self):
        t1 = self.client.app_info("SecurityClientTest")
        t2 = self.client.app_info("SecurityClientTest")
        nt.assert_equal(t1, t2)

    def test_appcache_same_target(self):
        t1 = self.client.app_info("SecurityClientTest", "Target")
        t2 = self.client.app_info("SecurityClientTest", "Target")
        nt.assert_equal(t1, t2)

    def test_appcache_diff_target(self):
        t1 = self.client.app_info("SecurityClientTest", "Target")
        t2 = self.client.app_info("SecurityClientTest", "NotSecurityClientTest")
        nt.assert_not_equal(t1, t2)

    def test_appcache_expire(self):
        EzSecurityClient.app_cache = TokenCache(0.5)
        t1 = self.client.app_info("SecurityClientTest")
        time.sleep(0.6)
        t2 = self.client.app_info("SecurityClientTest")
        nt.assert_not_equal(t1, t2)


class testEzSecurityClientMockMode(object):

    def test_mock_mode_no_dn(self):
        ezconf = EZConfiguration()
        ezconf.set("ezbake.security.ssl.dir", "test/certs/client")
        ezconf.set("ezbake.security.app.id", "SecurityClientTest")
        ezconf.set(ezsecurity.client.USE_MOCK_KEY, "true")

        client = EzSecurityClient(ezconf)
        nt.assert_raises(RuntimeError, client.user_info, None, None)

    def test_mock_mode(self):
        ezconf = EZConfiguration()
        ezconf.set("ezbake.security.ssl.dir", "test/certs/client")
        ezconf.set("ezbake.security.app.id", "SecurityClientTest")
        ezconf.set(ezsecurity.client.USE_MOCK_KEY, "true")
        ezconf.set(ezsecurity.client.MOCK_USER_DN, DN)

        client = EzSecurityClient(ezconf)
        token = client.user_info(None, None)
        nt.assert_is_not_none(token)

    def test_mock_mode_validate_received(self):
        ezconf = EZConfiguration()
        ezconf.set(ezsecurity.client.USE_MOCK_KEY, "true")
        ezconf.set(ezsecurity.client.MOCK_USER_DN, DN)
        client = EzSecurityClient(ezconf)

        nt.assert_true(client.validateReceivedToken(EzSecurityToken()))