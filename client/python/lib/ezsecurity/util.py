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
Created on Wed Nov 13 16:01:14 2013

@author: jhastings
"""
from collections import OrderedDict
import logging
import time
import base64
import thrift.TSerialization as tser
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5

current_time_millis = lambda: int(round(time.time() * 1000))


def verify(token, pubkey, owner, target=None):
    valid = False
    expires = token.response.expires

    # sort auths, formal access
    token.authorizations.externalCommunityAuthorizations.sort()
    token.authorizations.formalAuthorizations.sort()

    projects = token.response.securityInfo.projects
    if projects is not None:
        # sort projects
        od = OrderedDict(sorted(projects.items(), key=lambda t: t[0]))
        token.response.securityInfo.projects = od

    log = logging.getLogger(__name__)
    log.debug("verifying token {0}".format(token))

    if target is not None:
        log.info("Target not None, verifying target security ID")
        if token.response.targetSecurityId == target:
            log.info("Target security ID matches the passed target")
            if expires > current_time_millis():
                log.info("token expiration looks ok ({0} > {1})".format(expires, current_time_millis()))
                data = tser.serialize(token.response)
                sig = base64.b64decode(token.signature)
                log.info("verifying the signature")
                valid = verify_signature(data, sig, pubkey)
            else:
                log.info("expiration is bad ({0} > {1})".format(expires, current_time_millis()))
    elif token.response.securityId == owner:
        log.info("Verifying token for owner: {0}".format(owner))
        if expires > current_time_millis():
            log.info("token expiration looks ok ({0} > {1})".format(expires, current_time_millis()))
            data = tser.serialize(token.response)
            sig = base64.b64decode(token.signature)
            log.info("verifying the signature")
            valid = verify_signature(data, sig, pubkey)
        else:
            log.info("expiration is bad ({0} > {1})".format(expires, current_time_millis()))
    else:
        log.info("Not verifying token because target is none and the security ID doesn't match the owner")
    return valid


def verifySignedDn(dn, signature, pubKey):
    return verify_signature(dn, base64.b64decode(signature), pubKey)


def verify_signature(rawdata, signature, cert):
    # Not having x509 anymore. Use PyCrypto to verify instead
    #cert = ossl.load_certificate(ossl.FILETYPE_PEM, cert)
    #ossl.verify(cert, signature, rawdata, 'sha256')

    # verify response validity first
    key = RSA.importKey(cert)
    digest = SHA256.new(rawdata)
    verifier = PKCS1_v1_5.new(key)

    return verifier.verify(digest, signature)

import collections
class TokenCache(dict):
    def __init__(self, expire=2, *args, **kwarg):
        dargs = [ arg for arg in args if isinstance(arg, collections.Iterable)]
        if isinstance(expire, collections.Iterable):
            dargs.insert(0, expire)
            expire = 2
        super(TokenCache, self).__init__(*dargs, **kwarg)
        self.expire = expire

    def __process_get__(self, key, (exp, item)):
        if exp < current_time_millis():
            raise KeyError(key)
        return item

    def __getitem__(self, key):
        (exp, item) = super(TokenCache, self).__getitem__(key)
        return self.__process_get__(key, (exp, item))

    def get(self, key):
        (exp, item) = super(TokenCache, self).get(key)
        return self.__process_get__(key, (exp, item))

    def __setitem__(self, key, value):
        expires = current_time_millis() + int(self.expire*1000)
        super(TokenCache, self).__setitem__(key, (expires, value))
