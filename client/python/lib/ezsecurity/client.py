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
Created on Wed Nov 13 13:11:47 2013

@author: jhastings
"""
import logging
import base64
import OpenSSL.crypto as ossl

import thrift.TSerialization as tser
from thrift.protocol import TBinaryProtocol
from thrift.transport.TTransport import TTransportException

import ezconfiguration.helpers as EzC
import ezdiscovery
from ezsecurity.EzSSLSocket import SSLSocket
from ezsecurity.t import EzSecurity
from ezbakeBaseTypes.ttypes import TokenRequest
from ezbakeBaseTypes.ttypes import EzSecurityDn

import ezsecurity.util as util

USE_MOCK_KEY = "ezbake.security.client.use.mock"
MOCK_USER_DN = "ezbake.security.client.mock.user.dn"
MOCK_TARGET_ID_KEY = "ezbake.security.client.mock.target.id"

class EzSecurityClient(object):
    """
    Wrapper around the Ezbake Security thrift client

    Handles the PKI stuff surrounding request/response data in ezbake security
    """
    user_cache = util.TokenCache(60*60*2)
    app_cache = util.TokenCache(60*60*2)

    def __init__(self, ezconfig, log=logging.getLogger(__name__), handler=None):
        """
        Initializes the EzSecurityClient with all the required values
        @param targetApp: Application name expected in server cert
        @param host: host of thrift service to connect to
        @param port: port of thrift service to connect to
        @param ca: certificate authority with service's trusted cert
        @param cert: certificate to present to security service
        """
        self.ezconfig = ezconfig
        self.securityConfig = EzC.SecurityConfiguration(ezconfig)
        self.appConfig = EzC.ApplicationConfiguration(ezconfig)
        self.zooConfig = EzC.ZookeeperConfiguration(ezconfig)

        self.privateKey = None
        self.servicePublic = None

        self.log = log
        self.handler = handler

        self.connectors = []

        self.pzdiscovery = None
        self.transport = None

        self.mock = ezconfig.getBoolean(USE_MOCK_KEY, False)
        self.log.info("%s has mock config set to %s",
                      self.__class__.__name__, self.mock)

    def _ensure_pzd(self):
        """
        Ensures that PzDiscovery is connected
        """
        if self.pzdiscovery is None:
            ezdiscovery.connect(self.zooConfig.getZookeeperConnectionString())
            self.pzdiscovery = True

    def _ensure_keys(self):
        if self.privateKey is None:
            self.privateKey = self._readFile(self.securityConfig.privateKey())
        if self.servicePublic is None:
            self.servicePublic = self._readFile(self.securityConfig.servicePublic())

    def _getConnector(self):
        """
        Gets a connected thrift protcol for EzbakeSecurityService
        @throws TTransportException if unable to connect to EzbakeSecurityService
        """
        self._ensure_pzd();
        protocol = None

        for pt in ezdiscovery.get_common_endpoints(
            service_name='EzbakeSecurityService'):
            host, port = pt.split(':')
            try:
                transport = SSLSocket(
                    host, int(port), certfile=self.securityConfig.certs(),
                    keyfile=self.securityConfig.privateKey(),
                    ca_certs=self.securityConfig.caCerts())
                protocol = TBinaryProtocol.TBinaryProtocol(transport)
                self.log.info("connecting to EzbakeSecurityService on %s:%s",
                               host, port)
                transport.open()
        break
            except TTransportException as e:
                self.log.error("Unable to connect to %s:%s: %s", host, port, e)
                if transport is not None:
                    transport.close()
                    transport = None
                continue

        if protocol is None or not protocol.trans.isOpen():
            raise TTransportException(message="Unable to connect to security"
                                      "service with ezDiscovery")

        return protocol


    def _returnClient(self, client):
        """
        Return a thrift client to the pool of clients
        """
        self.connectors.append(client)

    def _getClient(self):
        """
        Get a thrift client for EzSecurity. First tries to get one from the
        pool, but gets a new connector if there isn't one
        """
        if self.connectors:
            client = self.connectors.pop()
            if not client._iprot.trans.isOpen():
                client._iprot.trans.open()
            if not client._oprot.trans.isOpen():
                client._iprot.trans.open()
        else:
            protocol = self._getConnector()
            client = EzSecurity.Client(protocol)

        return client

    def _readFile(self, filename):
        """
        Helper to read public/private keys where necessary
        @return the files bytes
        """
        with open(filename, 'r') as f:
            b = f.read()
        return b

    def _sign(self, data):
        """
        Sign some data using OpenSSL, and the application's certificate
        @return the base64 encodeded signature
        """
        self._ensure_keys()
        key = ossl.load_privatekey(ossl.FILETYPE_PEM, self.privateKey)
        return base64.b64encode(ossl.sign(key, data, 'sha256'))

    def _cache_key(self, targetApp, subject):
        return "{};{}".format(targetApp, subject)

    def ping(self):
        """
        Ping the security service
        @return true if the service is healthy
        """
        client = self._getClient()
        ret = client.ping()
        self._returnClient(client)
        return ret

    def _user_dn(self, dn):
        """
        Request a signed DN from the security service. Note this will most
        likely fail, since it only signs DNs for the EFE
        @param dn: the user's X509 subject
        @return an EzSecurityDn with a valid signature
        """
        request = self.build_request(dn, "")

        client = self._getClient()
        dn = client.requestUserDN(request, self._sign(tser.serialize(request)))
        self._returnClient(client)
        return dn

    def app_info(self, app, targetApp=None):
        """
        Request a token containing application info, optionally with a target
        securityId in the token. If the targetApp is specified, you will be
        able to send this token to another application, and it will validate on
        the other end. You should set txApp to
        ApplicationConfiguration(ezconfig).getSecurityID() if you are sending
        this to another thrift service within your application
        @param app: app to request info about
        @param targetApp: optionally, request security service to include a
        targetSecurityId in the token
        @return the EzSecurityToken
        """
        request = self.build_request(app, "", targetApp)

        # look in the cache
        cache_key = self._cache_key(targetApp, app)
        try:
            token = EzSecurityClient.app_cache[cache_key]
            if self._validateToken(token):
                self.log.info("Using token from cache")
                return token
            else:
                self.log.info("Token in cache was invalid. getting new")
        except KeyError:
            # it's not in the cache, continue
            pass

        client = self._getClient()

        self.log.info("Requesting app info for %s from EzSecurity", app)
        token = client.appInfo(request, self._sign(tser.serialize(request)))
        self.log.info("Received app info for %s from EzSecurity", app)

        self._returnClient(client)

        if not self._validateToken(token):
            self.log.error("Invalid token received from EzSecurity")
            token = None
        else:
            self.log.info("Storing app info %s in cache", app)
            EzSecurityClient.app_cache[cache_key] = token

        return token

    def user_info(self, dn, sig, targetApp=None):
        """
        Request a token with user info. Includes a targetSecurityId
        in the token if the txApp is passed. If targetSecurityId is set in the
        token, you will be able to pass this token to other thrift services.
        You should set txApp to
        ApplicationConfiguration(ezconfig).getSecurityID() if you are sending
        this to another thrift service within your application,
        @param dn: the user's dn, usually extracted from headers set by EFE
        @param sig: security service signed DN, usually extracted from headers
        set by EFE
        @param targetApp: optiaonlly, request security service to include a
        targetSecurityId in the token
        @return: the EzSecurityToken
        """
        if targetApp is None:
            targetApp = self.appConfig.getSecurityID()
        if sig is None:
            sig = ""
        if self.mock and dn is None:
            dn = self.ezconfig.get(MOCK_USER_DN)
            if dn is None:
                raise RuntimeError("{0} is in mock mode, but {1} is None".
                    format(self.__class__, MOCK_USER_DN))

        # look in the cache
        cache_key = self._cache_key(targetApp, dn)
        try:
            token = EzSecurityClient.user_cache[cache_key]
            if self._validateToken(token):
                self.log.info("Using token from cache")
                return token
            else:
                self.log.info("Token in cache was invalid. getting new")
        except KeyError:
            # it's not in the cache, continue
            pass

        client = self._getClient()
        request = self.build_request(dn, sig, targetApp)

        self.log.info("Requesting user info for %s from EzSecurity", dn)
        token = client.requestUserInfo(request,
                                       self._sign(tser.serialize(request)))
        self.log.info("Received user info for %s from EzSecurity", dn)
        if not self._validateToken(token):
            self.log.error("Invalid token received from EzSecurity")
            token = None
        else:
            self.log.info("Storing user info %s in cache", dn)
            EzSecurityClient.user_cache[cache_key] = token

        self._returnClient(client)
        return token

    def _validateToken(self, token):
        """
        Internal method for verifying tokens received from the security service
        @param token: the received EzSecurityToken
        @return: true if the token is valid
        """
        self._ensure_keys()
        return util.verify(token, self.servicePublic,
                           self.appConfig.getSecurityID(), None)

    def validateReceivedToken(self, token):
        """
        Validate a token that was received in a thrift request. This must be
        called whenever your application receives an EzSecurityToken from an
        unknown source (even if you think you know where it came from)
        @param token: the received EzSecurityToken
        @return: true if the token is valid
        """
        if self.mock:
            return True
        self._ensure_keys()
        return util.verify(token, self.servicePublic, None,
                           self.appConfig.getSecurityID())

    def validateSignedDn(self, dn, signature):
        """
        Validate a DN/Signature pair that is expected to have been signed by
        the security service
        @param dn: the dn
        @param signature: the security service signature
        @return: true if the DN validates
        """
        self._ensure_keys()
        return util.verifySignedDn(dn, signature, self.servicePublic)

    def build_request(self, dn, sig, targetApp=None):
        """
        Build a token request for the configuration
        @param dn: the user's dn
        @param sig: the signed dn
        @param txApp: the optional targetSecurityId
        @return: A TokenRequest for the request
        """
        token = TokenRequest()
        token.securityId = self.appConfig.getSecurityID()
        token.timestamp = util.current_time_millis()
        token.distinguishedName = EzSecurityDn(dn, sig)
        if targetApp is not None:
            token.targetSecurityId = targetApp
        return token
