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

// Anonymous HTTPS reader for the source documents, for a bucket whose manifests prefix is public.
//
// The S3 reader signs every request, so it needs credentials whether or not the object is public.
// This path needs none: it is a plain GET. What it does NOT give up is trust in the document —
// `sourcePublicKey` still has to verify the signature before anything is parsed, and that check is
// the reason a public prefix is tolerable at all. Reading a document is not the same as believing it.
//
// Deliberately read-only. In this configuration CI writes to the bucket directly, so there is
// nothing for the server to write and pretending otherwise would silently store a document where
// nothing reads it (see writeSourceManifest).

import ballerina/http;
import ballerina/log;
import ballerina/time;

final http:Client? manifestsClient = check initManifestsClient();

function initManifestsClient() returns http:Client?|error {
    if manifestsBaseUrl == "" {
        return ();
    }
    // followRedirects because a CDN in front of the bucket commonly 301s to a canonical host.
    return new (manifestsBaseUrl, {followRedirects: {enabled: true, maxCount: 3}});
}

// Same cache shape and semantics as the S3 reader, including caching a miss so repeated polls for a
// channel that has published nothing do not become one request per check.
isolated map<CachedS3Object> httpsCache = {};

isolated function readHttpsArtifact(string objectKey) returns [byte[], string]|error? {
    decimal now = <decimal>time:utcNow()[0];
    lock {
        CachedS3Object? cached = httpsCache[objectKey];
        if cached is CachedS3Object && now - cached.fetchedAt < s3CacheSeconds {
            byte[]? content = cached.content;
            if content is () {
                return ();
            }
            return [content.clone(), cached.etag];
        }
    }

    [byte[], string]|error? fetched = fetchHttpsObject(objectKey);
    if fetched is error {
        // A transient fetch failure must not poison the cache; the previous entry stays until a
        // later read succeeds.
        return fetched;
    }
    lock {
        if fetched is () {
            httpsCache[objectKey] = {content: (), etag: "", fetchedAt: now};
        } else {
            httpsCache[objectKey] = {content: fetched[0].clone(), etag: fetched[1], fetchedAt: now};
        }
    }
    return fetched;
}

// A 404 is reported as () — not published yet — while anything else is a real error, so a
// misconfigured base URL or a 403 surfaces instead of looking like an empty channel.
isolated function fetchHttpsObject(string objectKey) returns [byte[], string]|error? {
    http:Client? client_ = manifestsClient;
    if client_ is () {
        return error("HTTPS manifests store is not configured");
    }
    http:Response|error response = client_->get(string `/${objectKey}`);
    if response is error {
        return response;
    }
    if response.statusCode == 404 {
        return ();
    }
    if response.statusCode != 200 {
        return error(string `unexpected ${response.statusCode} reading ${objectKey} over HTTPS`);
    }
    byte[]|error content = response.getBinaryPayload();
    if content is error {
        return content;
    }
    log:printDebug(string `fetched ${manifestsBaseUrl}/${objectKey} (${content.length()} bytes)`);
    return [content, string `"${sha256Hex(content)}"`];
}
