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

from setuptools import setup, find_packages

setup(
    name='EzbakeSecurity',
    version='1.3',
    description='Libraries for working with ezbake security service',
    author='Jeff Hastings',
    author_email='jhastings@42six.com',
    url='www.ezbake.io',
    packages=find_packages('lib'),
    package_dir={
        '': 'lib',
    },
    install_requires=[
        # EzBake Deps
        'EzPyConfiguration==0.1.2',
        'ezdiscovery==0.2',
        # Other Python Deps
        'thrift==0.9.0',
        'pyOpenSSL==0.13.1',
        'pycrypto==2.6.1',
        # Testing
        'nose==1.3.0'
    ]
)
