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

var assert = require('assert');
var Int64 = require('node-int64');

var ezbakeBaseTypes = require('../../lib/thrift/ezbakeBaseTypes_types');
var ezbakeBaseAuthorizations = require('../../lib/thrift/ezbakeBaseAuthorizations_types');
var crypto = require('../../lib/crypto/rsaKeyCrypto');
var tu = require('../../lib/tokenUtils');

describe("TokenUtils", function() {
    describe("#serializeToken", function() {
        it("should serialize without throwing errors", function() {
            var str = tu.serializeToken(getTestToken());
            assert(str.toString());
        });
        it("should sort platform object authorizations before serializing", function() {
            var token = getTestToken();
            token.authorizations.platformObjectAuthorizations = [];
            var arr = [0, 295, 342, 77, 8];
            for (group in arr) {
                token.authorizations.platformObjectAuthorizations.push(new Int64(arr[group]));
            }
            var serialized = tu.serializeToken(token).toString();

            var search = "nanprotectservant";
            var start = serialized.toString().indexOf(search);

            var groupString = serialized.substr(start+search.length, arr.join("").length);

            console.log(groupString);
            assert(groupString === "0877295342");
        });
    });
});


function getTestToken() {
    var token = new ezbakeBaseTypes.EzSecurityToken();
    token.validity = new ezbakeBaseTypes.ValidityCaveats();
    token.validity.issuedTo = "SecurityClientTest";
    token.validity.issuedFor = "SecurityClientTest";
    token.validity.notAfter = 1403129951359;
    token.authorizationLevel = "servant";
    token.authorizations = new ezbakeBaseAuthorizations.Authorizations();
    token.authorizations.formalAuthorizations = ["Stark", "carry", "help", "nan", "protect", "servant"];
    token.externalProjectGroups = { "stark" : [ "winterfell", "bran" ] };

    var communityMembership = new ezbakeBaseTypes.CommunityMembership();
    communityMembership.name = "starkies";
    communityMembership.type = "familiar";
    communityMembership.organization = "stark";
    communityMembership.groups = [ "helpers" ];
    communityMembership.regions = [ "north" ];
    communityMembership.topics = [ "hodor", "honor" ];
    token.externalCommunities = [ communityMembership ];

    var userInfo = new ezbakeBaseTypes.EzSecurityPrincipal();
    userInfo.principal = "Hodor";
    userInfo.name = "Hodor";
    token.tokenPrincipal = userInfo;

    token.citizenship = "Stark";
    token.organization = "nan";

    return token;
}
