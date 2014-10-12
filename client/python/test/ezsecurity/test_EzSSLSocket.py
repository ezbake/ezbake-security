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
Created on Mon Nov 11 12:34:37 2013

@author: jhastings
"""
import nose.tools as nt

import os
import time
from multiprocessing import Process

from thrift.protocol import TBinaryProtocol
from thrift.transport import TTransport
from thrift.server import TServer
from thrift.transport.TTransport import TTransportException

from ezsecurity.EzSSLSocket import SSLSocket, SSLServerSocket
from ezsecurity.t import EzSecurity

PORT = 49875
capath = "test/certs/ezbakeca.crt"

servercertpath = "test/certs/server/application.crt"
serverprivpath = "test/certs/server/application.priv"

clientcertpath = "test/certs/client/application.crt"
clientprivpath = "test/certs/client/application.priv"

class EzSecurityHandler(object):
    def ping(self):
        return True


def start_service(port):
    try:
        handler = EzSecurityHandler()
        processor = EzSecurity.Processor(handler)
        transport = SSLServerSocket(port=port, ca_certs=capath, certfile=servercertpath, keyfile=serverprivpath)
        tfactory = TTransport.TBufferedTransportFactory()
        pFactory = TBinaryProtocol.TBinaryProtocolFactory()
        server = TServer.TSimpleServer(processor, transport, tfactory,
                                       pFactory)
        try:
            print "starting server on %s" % (PORT)
            server.serve()
        except (AttributeError, TTransportException) as e:
            print "Server error: ", e
            pass
    except (SystemExit, KeyboardInterrupt):
        return


class TestEzSSLSocket(object):
    def setUp(self):
        self.serverProcess = Process(target=start_service, args=(PORT,))
        self.serverProcess.start()
        time.sleep(1)

    def tearDown(self):
        if self.serverProcess.is_alive():
            self.serverProcess.terminate()

    def test_connect(self):
        transport = SSLSocket("localhost", PORT, ca_certs=capath, certfile=clientcertpath, keyfile=clientprivpath)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = EzSecurity.Client(protocol)
        transport.open()
        nt.assert_true(client.ping())
