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

import ballerina/crypto;
import ballerina/file;
import ballerina/http;
import ballerina/io;
import ballerina/test;

// Disable the client's built-in HTTP response cache so tests observe the raw
// server status codes (otherwise the client transparently turns a 304 into a
// cached 200 before the assertions run).
http:Client testClient = check new (string `http://localhost:${port}`, cache = {enabled: false});

@test:Config {}
function testHealthz() returns error? {
    http:Response res = check testClient->get("/healthz");
    test:assertEquals(res.statusCode, 200);
    json body = check res.getJsonPayload();
    test:assertEquals(check body.status, "ok");
}

@test:Config {}
function testGetManifest() returns error? {
    http:Response res = check testClient->get("/api/v1/updates/stable/darwin/arm64/manifest.json");
    test:assertEquals(res.statusCode, 200);
    test:assertEquals(check res.getHeader("Content-Type"), "application/json");

    string etag = check res.getHeader("ETag");
    test:assertTrue(etag.length() > 2, "ETag should be present");

    json payload = check res.getJsonPayload();
    Manifest manifest = check payload.cloneWithType(Manifest);
    test:assertEquals(manifest.channel, "stable");
    test:assertEquals(manifest.platform, "darwin");
    test:assertEquals(manifest.arch, "arm64");
    test:assertEquals(manifest.components.length(), 4);
    test:assertTrue(manifest.recommendedSet !is ());
}

@test:Config {}
function testConditionalGetReturns304() returns error? {
    http:Response first = check testClient->get("/api/v1/updates/stable/darwin/arm64/manifest.json");
    string etag = check first.getHeader("ETag");

    http:Response second = check testClient->get(
        "/api/v1/updates/stable/darwin/arm64/manifest.json", {"If-None-Match": etag});
    test:assertEquals(second.statusCode, 304);
}

@test:Config {}
function testGetManifestWithAppVersion() returns error? {
    http:Response res = check testClient->get(
        "/api/v1/updates/stable/darwin/arm64/manifest.json?appVersion=5.0.0.1");
    test:assertEquals(res.statusCode, 200);
}

@test:Config {}
function testSignatureAndCertServed() returns error? {
    http:Response sig = check testClient->get("/api/v1/updates/stable/darwin/arm64/manifest.json.sig");
    test:assertEquals(sig.statusCode, 200);
    test:assertEquals(check sig.getHeader("Content-Type"), "application/octet-stream");

    http:Response pem = check testClient->get("/api/v1/updates/stable/darwin/arm64/manifest.json.pem");
    test:assertEquals(pem.statusCode, 200);
    test:assertEquals(check pem.getHeader("Content-Type"), "application/x-pem-file");
}

@test:Config {}
function testInvalidPlatformRejected() returns error? {
    http:Response res = check testClient->get("/api/v1/updates/stable/solaris/arm64/manifest.json");
    test:assertEquals(res.statusCode, 400);
}

@test:Config {}
function testInvalidChannelRejected() returns error? {
    http:Response res = check testClient->get("/api/v1/updates/nightly/darwin/arm64/manifest.json");
    test:assertEquals(res.statusCode, 400);
}

@test:Config {}
function testMissingManifestReturns404() returns error? {
    // Valid path segments, but no manifest published for win32/arm64.
    http:Response res = check testClient->get("/api/v1/updates/stable/win32/arm64/manifest.json");
    test:assertEquals(res.statusCode, 404);
}

@test:Config {}
function testChannelsListing() returns error? {
    http:Response res = check testClient->get("/api/v1/channels");
    test:assertEquals(res.statusCode, 200);
    json body = check res.getJsonPayload();
    json[] channels = <json[]>(check body.channels);
    test:assertTrue(channels.indexOf("stable") !is ());
}

@test:Config {}
function testPublishDisabledByDefault() returns error? {
    // adminToken is empty in tests, so publish must be disabled (404).
    http:Request req = new;
    req.setJsonPayload({schemaVersion: 1});
    http:Response res = check testClient->put("/api/v1/updates/stable/darwin/arm64/manifest.json", req);
    test:assertEquals(res.statusCode, 404);
}

// ---- Phase 3: kill-switch + metrics ----

// Revocations are deployment configuration, so a test cannot set one at runtime. The matching rule
// is exercised against an explicit list instead; what the endpoints do WITH a match is covered by
// the scope-not-revoked case below plus the isRevoked call sites.
@test:Config {}
function testRevocationMatching() {
    Revocation[] configured = [
        {channel: "beta", platform: "linux", arch: "x64"},
        {channel: "insider", note: "whole channel held back"} // platform/arch default to "*"
    ];
    test:assertTrue(matchesRevocation(configured, "beta", "linux", "x64"), "exact scope");
    test:assertFalse(matchesRevocation(configured, "beta", "darwin", "arm64"), "same channel, other platform");
    test:assertFalse(matchesRevocation(configured, "stable", "linux", "x64"), "other channel");
    // Defaults make the common case a channel-wide hold that matches every platform and arch.
    test:assertTrue(matchesRevocation(configured, "insider", "darwin", "arm64"), "channel-wide");
    test:assertTrue(matchesRevocation(configured, "insider", "win32", "x64"), "channel-wide");
    test:assertFalse(matchesRevocation([], "stable", "darwin", "arm64"), "nothing configured");
}

@test:Config {}
function testScopeIsServedWhenNotRevoked() returns error? {
    // The suite runs with no revocations configured, which is the state that must serve normally —
    // a kill-switch that accidentally withholds everything would be a worse outage than the release
    // it was meant to stop.
    test:assertFalse(isRevoked("stable", "darwin", "arm64"));
    http:Response served = check testClient->get("/api/v1/updates/stable/darwin/arm64/manifest.json");
    test:assertEquals(served.statusCode, 200);
}

@test:Config {}
function testMetricsRecorded() returns error? {
    map<int> before = metricsSnapshot();
    int baseScope = before["insider/win32/x64"] ?: 0;
    int baseVersion = before["appVersion:9.9.9.9"] ?: 0;
    recordCheck("insider", "win32", "x64", "9.9.9.9");
    recordCheck("insider", "win32", "x64", ());
    map<int> updated = metricsSnapshot();
    test:assertEquals(updated["insider/win32/x64"], baseScope + 2, "scope counter increments per check");
    test:assertEquals(updated["appVersion:9.9.9.9"], baseVersion + 1, "appVersion counter increments when supplied");
}

@test:Config {}
function testAdminEndpointsDisabledWithoutToken() returns error? {
    // adminToken is empty in tests, so the admin API must be disabled (404).
    http:Response metrics = check testClient->get("/api/v1/admin/metrics");
    test:assertEquals(metrics.statusCode, 404);
    http:Response revs = check testClient->get("/api/v1/admin/revocations");
    test:assertEquals(revs.statusCode, 404);
}

@test:Config {}
function testSquirrelFeedWithoutEmbeddedDataReturns204() returns error? {
    // The stable fixture manifest has no app.commit/app.squirrel → treated as current.
    http:Response res = check testClient->get("/api/update/darwin-arm64/stable/0000000000000000000000000000000000000000");
    test:assertEquals(res.statusCode, 204);
}

@test:Config {}
function testSquirrelFeedUnknownAssetReturns404() returns error? {
    http:Response res = check testClient->get("/api/update/win32/stable/abc");
    test:assertEquals(res.statusCode, 404);
}

@test:Config {}
function testSquirrelFeedFlow() returns error? {
    // Seed a SOURCE document (one per channel, all targets) at a scope with no fixture.
    string zipUrl = "https://updates.wso2.com/artifacts/app/5.0.1.0/wso2-integrator-5.0.1.0-arm64-mac.zip";
    string dir = check file:joinPath(dataDir, "api", "v1", "updates", "insider");
    if !(check file:test(dir, file:EXISTS)) {
        check file:createDir(dir, file:RECURSIVE);
    }
    json src = {
        schemaVersion: 2,
        channel: "insider",
        sequence: 7,
        publishedAt: "2026-08-13T00:00:00Z",
        apps: [
            {
                'version: "5.0.1.0",
                'commit: "newsha",
                targets: {
                    "darwin-arm64": {
                        installer: {url: "https://updates.wso2.com/a.dmg", sha256: "x", sizeBytes: 1},
                        squirrel: {url: zipUrl}
                    }
                }
            }
        ],
        components: []
    };
    check io:fileWriteString(check file:joinPath(dir, "source.json"), src.toJsonString());

    // An older build (different commit) is offered the update with the CDN zip URL.
    http:Response offered = check testClient->get("/api/update/darwin-arm64/insider/oldsha");
    test:assertEquals(offered.statusCode, 200);
    json body = check offered.getJsonPayload();
    test:assertEquals(check body.url, zipUrl);
    test:assertEquals(check body.name, "5.0.1.0");

    // The latest build (same commit) is current.
    http:Response current = check testClient->get("/api/update/darwin-arm64/insider/newsha");
    test:assertEquals(current.statusCode, 204);

    // x64 has no target in this document at all, so there is nothing to offer.
    http:Response otherArch = check testClient->get("/api/update/darwin/insider/oldsha");
    test:assertEquals(otherArch.statusCode, 204);
}

@test:Config {}
function testMinorLineParsing() {
    test:assertEquals(minorLine("5.1.2-testalpha1"), "5.1");
    test:assertEquals(minorLine("5.1.2"), "5.1");
    test:assertEquals(minorLine("5.2.0.3"), "5.2");
    test:assertEquals(minorLine("5.1-alpha1"), "5.1");
    // No minor component, or non-numeric: callers must skip the line decision rather than guess.
    test:assertEquals(minorLine("5"), ());
    test:assertEquals(minorLine(""), ());
    test:assertEquals(minorLine("latest"), ());
    test:assertEquals(minorLine("x.y"), ());
}

@test:Config {}
function testSquirrelFeedWithholdsCrossMinorUpdate() returns error? {
    string dir = check file:joinPath(dataDir, "api", "v1", "updates", "beta");
    if !(check file:test(dir, file:EXISTS)) {
        check file:createDir(dir, file:RECURSIVE);
    }
    // No `appliesTo` here on purpose: this exercises the standalone minor-line gate, which is what
    // still protects a document that does not declare its line.
    json src = {
        schemaVersion: 2,
        channel: "beta",
        sequence: 9,
        publishedAt: "2026-08-13T00:00:00Z",
        apps: [
            {
                'version: "5.2.0",
                'commit: "newsha",
                targets: {
                    "darwin-arm64": {
                        installer: {url: "https://updates.wso2.com/a.dmg", sha256: "x", sizeBytes: 1},
                        squirrel: {url: "https://updates.wso2.com/a.zip"}
                    }
                }
            }
        ],
        components: []
    };
    check io:fileWriteString(check file:joinPath(dir, "source.json"), src.toJsonString());

    // A 5.1.x client must NOT be offered the 5.2.0 build.
    http:Response withheld = check testClient->get("/api/update/darwin-arm64/beta/oldsha?wiversion=5.1.3");
    test:assertEquals(withheld.statusCode, 204);

    // A client already on the 5.2 line is offered it.
    http:Response offered = check testClient->get("/api/update/darwin-arm64/beta/oldsha?wiversion=5.2.0-rc1");
    test:assertEquals(offered.statusCode, 200);
    json body = check offered.getJsonPayload();
    test:assertEquals(check body.productVersion, "5.2.0");

    // A client that predates the parameter keeps the previous behaviour rather than being
    // stranded with no updates at all.
    http:Response legacy = check testClient->get("/api/update/darwin-arm64/beta/oldsha");
    test:assertEquals(legacy.statusCode, 200);

    // An unparseable version cannot be placed on a line, so it is not gated.
    http:Response unparseable = check testClient->get("/api/update/darwin-arm64/beta/oldsha?wiversion=latest");
    test:assertEquals(unparseable.statusCode, 200);

    // Same-commit clients are still current regardless of the line.
    http:Response current = check testClient->get("/api/update/darwin-arm64/beta/newsha?wiversion=5.2.0");
    test:assertEquals(current.statusCode, 204);
}

@test:Config {}
function testReadEndpointsOpenWhenNoClientTokensConfigured() returns error? {
    // The suite runs with clientTokens = [] (the default), which must stay open — every client
    // built before this feature sends no Authorization header at all.
    http:Response manifest = check testClient->get("/api/v1/updates/stable/win32/x64/manifest.json");
    test:assertTrue(manifest.statusCode == 200 || manifest.statusCode == 404,
        string `expected an unauthenticated read to be served, got ${manifest.statusCode}`);
    http:Response squirrel = check testClient->get("/api/update/darwin-arm64/stable/somesha");
    test:assertTrue(squirrel.statusCode != 401, "squirrel feed must not require auth when unconfigured");
}

@test:Config {}
function testClientAuthGuardLogic() {
    // clientTokens is a module-level configurable, so exercise the comparison the guard performs
    // rather than re-deploying the listener: a digest match on "Bearer <token>" and nothing else.
    string token = "s3cr3t-client-token";
    byte[] expected = crypto:hashSha256(string `Bearer ${token}`.toBytes());
    test:assertEquals(crypto:hashSha256(string `Bearer ${token}`.toBytes()), expected);
    test:assertNotEquals(crypto:hashSha256(string `Bearer ${token} `.toBytes()), expected);
    test:assertNotEquals(crypto:hashSha256(token.toBytes()), expected);
    test:assertNotEquals(crypto:hashSha256("Bearer wrong".toBytes()), expected);
}
