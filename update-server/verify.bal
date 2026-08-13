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

import ballerina/jballerina.java;
import ballerina/jballerina.java.arrays as jarrays;
import ballerina/lang.array;

// Verifies the source document's detached cosign signature.
//
// This goes through Java rather than ballerina/crypto because cosign's public key is a bare SPKI
// PEM ("BEGIN PUBLIC KEY"), and the crypto module can only decode an EC public key from an X.509
// certificate or a truststore — there is no bare-PEM EC path. Rather than reshape the key material
// to suit the binding, the standard JCA route is used directly.
//
// cosign signs with ECDSA-P256/SHA-256 and emits DER, which is what SHA256withECDSA verifies.

isolated function keyFactoryGetInstance(handle algorithm) returns handle|error = @java:Method {
    name: "getInstance",
    'class: "java.security.KeyFactory",
    paramTypes: ["java.lang.String"]
} external;

isolated function newX509EncodedKeySpec(handle der) returns handle = @java:Constructor {
    'class: "java.security.spec.X509EncodedKeySpec",
    paramTypes: ["[B"]
} external;

isolated function generatePublic(handle keyFactory, handle keySpec) returns handle|error = @java:Method {
    name: "generatePublic",
    'class: "java.security.KeyFactory",
    paramTypes: ["java.security.spec.KeySpec"]
} external;

isolated function signatureGetInstance(handle algorithm) returns handle|error = @java:Method {
    name: "getInstance",
    'class: "java.security.Signature",
    paramTypes: ["java.lang.String"]
} external;

isolated function signatureInitVerify(handle signature, handle publicKey) returns error? = @java:Method {
    name: "initVerify",
    'class: "java.security.Signature",
    paramTypes: ["java.security.PublicKey"]
} external;

isolated function signatureUpdate(handle signature, handle data) returns error? = @java:Method {
    name: "update",
    'class: "java.security.Signature",
    paramTypes: ["[B"]
} external;

isolated function signatureVerify(handle signature, handle signatureBytes) returns boolean|error = @java:Method {
    name: "verify",
    'class: "java.security.Signature",
    paramTypes: ["[B"]
} external;

// Strips the PEM armour and base64-decodes the body, yielding DER SPKI bytes.
isolated function pemToDer(string pem) returns byte[]|error {
    string body = "";
    foreach string line in re `\n`.split(pem) {
        string trimmed = line.trim();
        if trimmed.length() == 0 || trimmed.startsWith("-----") {
            continue;
        }
        body = body + trimmed;
    }
    if body.length() == 0 {
        return error("public key PEM contains no base64 body");
    }
    return array:fromBase64(body);
}

// true when `signatureBase64` is a valid ECDSA-P256/SHA-256 signature over `data` for `publicKeyPem`.
public isolated function verifyDetachedSignature(byte[] data, string signatureBase64, string publicKeyPem)
        returns boolean|error {
    byte[] der = check pemToDer(publicKeyPem);
    byte[] signatureBytes = check array:fromBase64(signatureBase64.trim());
    handle keyFactory = check keyFactoryGetInstance(java:fromString("EC"));
    handle keySpec = newX509EncodedKeySpec(check jarrays:toHandle(der, "byte"));
    handle publicKey = check generatePublic(keyFactory, keySpec);
    handle verifier = check signatureGetInstance(java:fromString("SHA256withECDSA"));
    check signatureInitVerify(verifier, publicKey);
    check signatureUpdate(verifier, check jarrays:toHandle(data, "byte"));
    return signatureVerify(verifier, check jarrays:toHandle(signatureBytes, "byte"));
}
