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
Created on Wed Apr 16 08:37:58 2014

@author: jhastings
"""
import nose.tools as nt
import time
from ezsecurity.util import TokenCache

class TestTokenCache(object):

    def test_behaves_like_dict(self):
        a = TokenCache(one=1, two=2, three=3)
        b = TokenCache(zip(['one', 'two', 'three'], [1, 2, 3]))
        c = TokenCache([('two', 2), ('one', 1), ('three', 3)])
        d = TokenCache({'three': 3, 'one': 1, 'two': 2})
        nt.assert_true(a == b == c == d)

    def test_has_default_expire(self):
        a = TokenCache(one=1, two=2, three=3)
        b = TokenCache(zip(['one', 'two', 'three'], [1, 2, 3]))
        c = TokenCache([('two', 2), ('one', 1), ('three', 3)])
        d = TokenCache({'three': 3, 'one': 1, 'two': 2})
        nt.assert_equal(2, a.expire)
        nt.assert_equal(2, b.expire)
        nt.assert_equal(2, c.expire)
        nt.assert_equal(2, d.expire)

    def test_can_pass_expire(self):
        a = TokenCache(1, one=1, two=2, three=3)
        b = TokenCache(2, zip(['one', 'two', 'three'], [1, 2, 3]))
        c = TokenCache(3, [('two', 2), ('one', 1), ('three', 3)])
        d = TokenCache(4, {'three': 3, 'one': 1, 'two': 2})
        nt.assert_equal(1, a.expire)
        nt.assert_equal(2, b.expire)
        nt.assert_equal(3, c.expire)
        nt.assert_equal(4, d.expire)

    def test_assign_has_expire(self):
        cache = TokenCache(2);
        cache['key'] = 9
        value = super(TokenCache, cache).get('key')
        nt.assert_is_instance(value, tuple)
        nt.assert_is_instance(value[0], int)

    def test_iter_has_expire(self):
        cache = TokenCache(2);
        cache['key'] = 9
        cache['key2'] = 10
        for key in cache:
            value = super(TokenCache, cache).get(key)
            nt.assert_is_instance(value, tuple)
            nt.assert_is_instance(value[0], int)

    def test_values_expire(self):
        cache = TokenCache(0.5);
        cache['key'] = 9
        nt.assert_equal(9, cache['key'])
        nt.assert_equal(9, cache.get('key'))
        time.sleep(0.6)
        nt.assert_raises(KeyError, cache.get, 'key')
        nt.assert_raises(KeyError, cache.__getitem__, 'key')
