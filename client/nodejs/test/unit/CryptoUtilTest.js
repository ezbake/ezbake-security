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

/**
 * @author Gary Drocella
 * @date 01/03/14
 */
 
var assert = require("assert");
var fs = require("fs");

var CryptoUtil = require("../../lib/crypto/CryptoUtil.js");
 
describe("CryptoUtil", function() {
	describe("#stripPEMString", function() {
		it("Should strip a PEM String..", function() {
                    var clean ="MIIEowIBAAKCAQEAuwwhEREWsbLP692R5aATgBJcPQyNs0YclOc6I4lTEuow/I32"+
                        "aSh98wWKPlPCUGWWo3H3PUce1O/dzfCI8da0W78s910n9Oqe0nNZCfOvs/gVtxT9"+
                        "hECqhYw35q997kRalUmc8Qif2EATtsRNDLO3VZlWrg9U9HyyJxchLTl9STUJe6GS"+
                        "JWA/gfQk9+UWaaasVawvnQr39EWe7sdfm3/QCF1N9C9afcKpqMzwUdQ8GdfIvASy"+
                        "x/M/ON6S9ct7VKyJzO82saPv/u2yy6fV1Bb66DYsi7j9ILXm+A+xrw8rirwuMK4X"+
                        "4srahrfBJOv1zFTOoiIAG2HRl+8dIv0VQ37K/wIDAQABAoIBAAOc/l6IB/oyzBVw"+
                        "WEspRnco46NCRNJ7vj2aIeNh2br5zyxxyZrKb3RsXPlLQOuwqrJJl08VuqC+aXh6"+
                        "9wpE7YMANGwq3oS6q4rBM60fifteBX1d6G/Pl/uwc7v/E92wcFeF7oQxeHUC996F"+
                        "+D8QkbAToDsIjMmURxS+O6PWAneRiEKW2SZ5qgezcCSwK3Aly/SIEAC1OkOEUCMs"+
                        "txljPT78wPzqpDjFafn3Xgw4/bwJridW/f2GYZm7toADIswULcRpg4zoWtjh9N18"+
                        "Ju/yFnwvkbnVBYFZ6d6JYy4IIJ9Ur567JLRaeXNE/lzr5loCNwiGXh16l9koMRPp"+
                        "nu+1CrECgYEA32djRTczYa6k4OgRLEHxeMkZY6OkNBOID/DngynnR9JPro2z0r3j"+
                        "w65kjqKsjwHXZkWnw1rGJXxUJwKay9zHuC4DKT0DX1WWn65uQ/y6vHJRmxOMrDFJ"+
                        "/kk6zU6qOCNFIiwrifyRMKRE6nvS0Z14E3xM/HpIM76ANPBzpP/DAssCgYEA1la/"+
                        "xMbIEBow9zIj9whRSbndgc8XtMOBXpCB+sEy5Mc9wQi7MvB5pC62By0gADJoSF97"+
                        "zpBJLr5MF+Kus6vd+YoJlUGwYx2mzAxwFNrK+AkXix6k9+MAfWtxdhYe2nCAj5K2"+
                        "b0PQJhglqv//ADU364drVIuFu9PDYk/rIyfVLh0CgYB/t+Cl4nAKiUiTl7ixn6WI"+
                        "ExfjwdsPNpdT3brNXrhtdAu/1B0Y/xxmc53jeZbDTx8wxeOqKIwdRB3sC24p3DeF"+
                        "0TBXdB0odIrfEV7SmXq8X3LOAHgsvST7Lixi0XU5ENjmN3BQu8bZkyAfGdkloyvR"+
                        "n/93XAVJJ8CuA0Vp8BoxzwKBgEFNVsneAlAdmrOFnD2EVDfRH/KPpNpXAlBMWL2M"+
                        "JTRcm6z3OwmPCJCEBsNy9R/6O5lpNfA+N329TrOsRavJ/iwr6TWHOPVJsGrUk0VX"+
                        "T6V4J6skIADCMYEEviHLJYVJ53FWsqx9jao9iyRpMEjg7fOdY47zn0AViZ6nWK1y"+
                        "UlnlAoGBAIN/FRO4PkGSdSNhNsrXo+sOgspbZWkxKfWEuKsoH2BIf9EnNgAMFiIR"+
                        "O70nle8lOj8delITvs5N1NnlNebpVobEHvzYIgA5HHq8l6Xe83eTfD/XVgsyTIO+"+
                        "YJRuhAiY4XHP3g4qPL6mNCfYGb/2JlqTkwijQpcgr83qPakZG+sT";

			var content = fs.readFileSync('test/conf/server/application.priv', "utf8");
		        var cleaned = CryptoUtil.stripPEMString(content.toString());

			assert(clean == cleaned);
		})
	 })
});

describe("CryptoUtil", function() {
	describe("#decode", function() {
		it("Should decode base64 string into ascii.", function() {
			var encodedStr = "Zm9vYmFy";
			assert("foobar" == CryptoUtil.decode(encodedStr));
		    })
	})
});


describe("CryptoUtil", function() {
	describe("#der", function() {
		it("Should strip the PEM string, and then decode the base64 encoded string", function() {
			var input = "-----BEGIN RSA PRIVATE KEY-----\n" +
			             "MTk=\n" +
			             "-----END RSA PRIVATE KEY-----\n";
			assert(19 == CryptoUtil.der(input));
		    })
	    })
});
