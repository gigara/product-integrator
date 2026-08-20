// Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/lang.array;
import ballerina/test;

// A real ECDSA-P256/SHA-256 signature over TEST_DOC, produced the same way cosign signs a blob.
const string TEST_PUBLIC_KEY_B64 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFMGlzVGtvb2J3NFJ0ZTJudzV1SkxHWUNTbUptYwpCcHhUb1Rxd2pWc3VIL2l2bGV6WjBMMDZNby94Tk5GZ1Qrd3IrK3BYcm41S2xVYlBkY0JreEg4cmF3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";
const string TEST_SIGNATURE_B64 = "MEQCIC89hRN2ZrHjkDdcXDf2Y1nK2EsWD+dFIYsRYe5I8EYFAiByLxV6nKWxrG0H5PFS8fpqMnKIAZz2m+SDcDSWw+7tNw==";
// The exact bytes the signature above was produced over. NOT a schema-valid source document, and it
// must not be "corrected" into one: the signature is over these bytes, so editing the string breaks
// the test it exists for. Schema shape is covered by the decide/service tests.
const string TEST_DOC = "{\"schemaVersion\":2,\"channel\":\"stable\",\"sequence\":1}";

function testPublicKeyPem() returns string|error {
    byte[] pem = check array:fromBase64(TEST_PUBLIC_KEY_B64);
    return string:fromBytes(pem);
}

@test:Config {}
function testVerifiesAGenuineSignature() returns error? {
    string pem = check testPublicKeyPem();
    boolean ok = check verifyDetachedSignature(TEST_DOC.toBytes(), TEST_SIGNATURE_B64, pem);
    test:assertTrue(ok, "a genuine signature over the document must verify");
}

@test:Config {}
function testRejectsATamperedDocument() returns error? {
    string pem = check testPublicKeyPem();
    // One digit changed: the signature is still genuine, but not for THIS document — which is the
    // case that matters, since a compromised bucket can replace the document but not re-sign it.
    string tampered = "{\"schemaVersion\":2,\"channel\":\"stable\",\"sequence\":2}";
    boolean ok = check verifyDetachedSignature(tampered.toBytes(), TEST_SIGNATURE_B64, pem);
    test:assertFalse(ok, "a document that was not signed must be rejected");
}

@test:Config {}
function testRejectsGarbageAndMalformedInput() returns error? {
    string pem = check testPublicKeyPem();
    // Well-formed base64 that is not a signature: rejected, not accepted and not a crash.
    boolean|error wrongSig = verifyDetachedSignature(TEST_DOC.toBytes(), "AAAA", pem);
    test:assertTrue(wrongSig is error || wrongSig == false);
    // Not base64 at all.
    boolean|error garbage = verifyDetachedSignature(TEST_DOC.toBytes(), "!!!not-base64!!!", pem);
    test:assertTrue(garbage is error || garbage == false);
    // A PEM with no body.
    boolean|error emptyKey = verifyDetachedSignature(TEST_DOC.toBytes(), TEST_SIGNATURE_B64, "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----");
    test:assertTrue(emptyKey is error, "an empty key must error rather than verify");
}
