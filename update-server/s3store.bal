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

// S3-backed artifact store with a small in-memory read cache.
//
// Active when `s3Bucket` is configured: manifests and Squirrel feeds are read from
// s3://<s3Bucket>/manifests/<channel>/<platform>/<arch>/<file> — the layout the CI
// publish-update-manifest job writes. Bytes are served VERBATIM (the detached cosign
// signature must stay valid), and both hits and misses are cached for s3CacheSeconds
// so background update polls from every client don't translate into S3 reads.

import ballerina/log;
import ballerina/time;
import ballerinax/aws.s3;

// Created once at startup; () when the server runs in local (dataDir) mode.
// Misconfiguration (e.g. bucket set but bad credentials shape) fails startup loudly.
final s3:Client? s3Client = check initS3Client();

function initS3Client() returns s3:Client?|error {
    if s3Bucket == "" {
        return ();
    }
    s3:ConnectionConfig connectionConfig = {
        accessKeyId: s3AccessKeyId,
        secretAccessKey: s3SecretAccessKey,
        region: s3Region
    };
    return new (connectionConfig);
}

// A cached S3 object. `content == ()` records a miss (object not published yet) so
// repeated polls for an absent file don't hit S3 each time either.
type CachedS3Object record {|
    byte[]? content;
    string etag;
    decimal fetchedAt;
|};

isolated map<CachedS3Object> s3Cache = {};

// Reads an object from the bucket via the cache. Returns () when the object does not
// exist, [bytes, etag] on success, or an error on real S3 failures (never cached).
isolated function readS3Artifact(string objectKey) returns [byte[], string]|error? {
    decimal now = <decimal>time:utcNow()[0];
    lock {
        CachedS3Object? cached = s3Cache[objectKey];
        if cached is CachedS3Object && now - cached.fetchedAt < s3CacheSeconds {
            byte[]? content = cached.content;
            if content is () {
                return ();
            }
            return [content.clone(), cached.etag];
        }
    }

    [byte[], string]|error? fetched = fetchS3Object(objectKey);
    if fetched is error {
        // Transient S3 failure: don't poison the cache; the previous entry (if any)
        // simply stays until a later fetch succeeds.
        return fetched;
    }
    lock {
        if fetched is () {
            s3Cache[objectKey] = {content: (), etag: "", fetchedAt: now};
        } else {
            s3Cache[objectKey] = {content: fetched[0].clone(), etag: fetched[1], fetchedAt: now};
        }
    }
    return fetched;
}

// Performs the real S3 read. A missing object is reported as () rather than an error.
isolated function fetchS3Object(string objectKey) returns [byte[], string]|error? {
    s3:Client? s3 = s3Client;
    if s3 is () {
        return error("S3 store is not configured");
    }
    stream<byte[], error?>|error result = s3->getObject(s3Bucket, objectKey);
    if result is error {
        if isS3NotFound(result) {
            return ();
        }
        return result;
    }
    byte[] content = [];
    while true {
        record {|byte[] value;|}|error? next = result.next();
        if next is () {
            break;
        }
        if next is error {
            if isS3NotFound(next) {
                return ();
            }
            return next;
        }
        foreach byte b in next.value {
            content.push(b);
        }
    }
    log:printDebug(string `fetched s3://${s3Bucket}/${objectKey} (${content.length()} bytes)`);
    return [content, string `"${sha256Hex(content)}"`];
}

// Writes an object (admin publish write-through in S3 mode).
isolated function writeS3Artifact(string objectKey, byte[] content) returns error? {
    s3:Client? s3 = s3Client;
    if s3 is () {
        return error("S3 store is not configured");
    }
    check s3->createObject(s3Bucket, objectKey, content);
    lock {
        _ = s3Cache.removeIfHasKey(objectKey);
    }
}

// The connector surfaces a missing object as a generic error; match the S3 error code.
isolated function isS3NotFound(error e) returns boolean {
    string message = e.message();
    return message.includes("NoSuchKey") || message.includes("Not Found") || message.includes("404");
}
