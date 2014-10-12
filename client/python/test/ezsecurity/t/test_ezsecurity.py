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
Created on Tue Apr 15 08:15:33 2014

@author: jhastings
"""
import nose.tools as nt
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

import ezsecurity.t.EzSecurity

class TestEzSecurity(object):
    """
    Test that the generated thrift code is well
    """

    def test_create_client(self):
        """Just making sure that I can create an EzSecurity.Client"""
        transport = TSocket.TSocket()
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ezsecurity.t.EzSecurity.Client(protocol)
        nt.assert_is_instance(client, ezsecurity.t.EzSecurity.Client)
