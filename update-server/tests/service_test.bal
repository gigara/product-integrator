import ballerina/file;
import ballerina/http;
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

@test:Config {}
function testRevocationRoundTrip() returns error? {
    test:assertFalse(isRevoked("beta", "linux", "x64"), "not revoked initially");
    _ = check setRevocation("beta", "linux", "x64", true);
    test:assertTrue(isRevoked("beta", "linux", "x64"), "revoked after set");
    // A channel-wide (wildcard) revocation matches any platform/arch.
    _ = check setRevocation("beta", "*", "*", true);
    test:assertTrue(isRevoked("beta", "darwin", "arm64"), "channel-wide revocation matches any scope");
    _ = check setRevocation("beta", "linux", "x64", false);
    _ = check setRevocation("beta", "*", "*", false);
    test:assertFalse(isRevoked("beta", "linux", "x64"), "cleared exact scope");
    test:assertFalse(isRevoked("beta", "darwin", "arm64"), "cleared wildcard");
}

@test:Config {}
function testKillSwitchWithholdsManifest() returns error? {
    _ = check setRevocation("stable", "darwin", "arm64", true);
    http:Response revoked = check testClient->get("/api/v1/updates/stable/darwin/arm64/manifest.json");
    test:assertEquals(revoked.statusCode, 204, "revoked scope withholds the manifest (no update)");
    _ = check setRevocation("stable", "darwin", "arm64", false);
    http:Response restored = check testClient->get("/api/v1/updates/stable/darwin/arm64/manifest.json");
    test:assertEquals(restored.statusCode, 200, "cleared scope serves the manifest again");
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

// Remove the revocation file created by the kill-switch tests so it isn't left in the repo.
@test:AfterSuite {}
function cleanupRevocations() returns error? {
    string path = check file:joinPath(dataDir, "revocations.json");
    if check file:test(path, file:EXISTS) {
        check file:remove(path);
    }
}
