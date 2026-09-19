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

// Product-scoped routes: each product flavor reads its own isolated store prefix, and the
// non-negotiable invariant is isolation BOTH ways — the integrator's documents are never
// served on /agent-builder/... and agent-builder documents never on the bare routes.

import ballerina/file;
import ballerina/http;
import ballerina/io;
import ballerina/test;

@test:Config {}
function testProductScopeKeys() {
    test:assertEquals(productScope("integrator", "insider"), "insider",
        "the integrator keeps today's bare channel keys");
    test:assertEquals(productScope("agent-builder", "insider"), "agent-builder/insider");
    test:assertTrue(knownProduct("agent-builder"), "default allowlist carries agent-builder");
    test:assertFalse(knownProduct("integrator"),
        "'integrator' is the bare routes, never a prefix segment");
    test:assertFalse(knownProduct("nonsense"));
}

@test:Config {}
function testUnknownProductIs404() returns error? {
    http:Response channels = check testClient->get("/nonsense/api/v1/channels");
    test:assertEquals(channels.statusCode, 404);
    http:Response squirrel = check testClient->get("/nonsense/api/update/darwin-arm64/stable/abc");
    test:assertEquals(squirrel.statusCode, 404);
    http:Request req = new;
    req.setJsonPayload({platform: "darwin", arch: "arm64", appVersion: "1.0.0", components: {}});
    http:Response updates = check testClient->post("/nonsense/api/v1/updates", req);
    test:assertEquals(updates.statusCode, 404);
    // 'integrator' is served by the bare routes only; as a prefix it is not a product.
    http:Response integratorPrefixed = check testClient->get("/integrator/api/v1/channels");
    test:assertEquals(integratorPrefixed.statusCode, 404);
}

@test:Config {}
function testProductChannelsRoute() returns error? {
    http:Response res = check testClient->get("/agent-builder/api/v1/channels");
    test:assertEquals(res.statusCode, 200);
}

@test:Config {}
function testEmptyProductChannelIs204() returns error? {
    // Nothing published for agent-builder stable: an empty channel is "no updates", never an error.
    http:Request req = new;
    req.setJsonPayload({channel: "stable", platform: "darwin", arch: "arm64", appVersion: "1.0.0", components: {}});
    http:Response res = check testClient->post("/agent-builder/api/v1/updates", req);
    test:assertEquals(res.statusCode, 204);
    http:Response squirrel = check testClient->get("/agent-builder/api/update/darwin-arm64/stable/somesha");
    test:assertEquals(squirrel.statusCode, 204);
}

@test:Config {}
function testProductPublishStaysDisabledWithoutAdminToken() returns error? {
    http:Request req = new;
    req.setJsonPayload({schemaVersion: 1});
    http:Response res = check testClient->put("/agent-builder/api/v1/updates/stable/source.json", req);
    test:assertEquals(res.statusCode, 404);
}

// Seeds one document per product on the SAME channel ("beta", untouched by the other tests) with
// distinct versions/URLs, then asserts each product's routes serve only its own document.
@test:Config {}
function testProductIsolationBothWays() returns error? {
    string integratorZip = "https://updates.wso2.com/artifacts/app/9.1.0/wso2-integrator-9.1.0-arm64-mac.zip";
    string agentZip = "https://updates.wso2.com/artifacts/agent-builder/app/0.2.0/wso2-agent-builder-0.2.0-arm64-mac.zip";

    check seedSquirrelDoc(check file:joinPath(dataDir, "api", "v1", "updates", "beta"),
        "9.1.0", "integratorsha", integratorZip);
    check seedSquirrelDoc(check file:joinPath(dataDir, "api", "v1", "updates", "agent-builder", "beta"),
        "0.2.0", "agentsha", agentZip);

    // Each product's feed serves its own document...
    http:Response integratorOffer = check testClient->get("/api/update/darwin-arm64/beta/oldsha");
    test:assertEquals(integratorOffer.statusCode, 200);
    json integratorBody = check integratorOffer.getJsonPayload();
    test:assertEquals(check integratorBody.url, integratorZip);
    test:assertEquals(check integratorBody.name, "9.1.0");

    http:Response agentOffer = check testClient->get("/agent-builder/api/update/darwin-arm64/beta/oldsha");
    test:assertEquals(agentOffer.statusCode, 200);
    json agentBody = check agentOffer.getJsonPayload();
    test:assertEquals(check agentBody.url, agentZip);
    test:assertEquals(check agentBody.name, "0.2.0");

    // ...and never the other's: each product's current commit is "up to date" only on its own
    // route. If either route read the other's document, the commit would differ and a 200 with
    // the wrong product's payload would come back instead of the 204.
    http:Response integratorCurrent = check testClient->get("/api/update/darwin-arm64/beta/integratorsha");
    test:assertEquals(integratorCurrent.statusCode, 204, "integrator route must read only the integrator document");
    http:Response agentCurrent = check testClient->get("/agent-builder/api/update/darwin-arm64/beta/agentsha");
    test:assertEquals(agentCurrent.statusCode, 204, "agent-builder route must read only the agent-builder document");
}

// Kill-switch scoping: an integrator channel revocation must not withhold the same channel of
// another product, and vice versa — the scoped-channel keys are what keeps them apart.
@test:Config {}
function testRevocationScopesPerProduct() {
    Revocation[] integratorHold = [{channel: "insider"}];
    test:assertTrue(matchesRevocation(integratorHold, productScope("integrator", "insider"), "darwin", "arm64"));
    test:assertFalse(matchesRevocation(integratorHold, productScope("agent-builder", "insider"), "darwin", "arm64"),
        "an integrator revocation must not silently stop agent-builder");
    Revocation[] agentHold = [{channel: "agent-builder/insider"}];
    test:assertFalse(matchesRevocation(agentHold, productScope("integrator", "insider"), "darwin", "arm64"),
        "an agent-builder revocation must not silently stop the integrator");
    test:assertTrue(matchesRevocation(agentHold, productScope("agent-builder", "insider"), "darwin", "arm64"));
}

function seedSquirrelDoc(string dir, string version, string commitSha, string zipUrl) returns error? {
    if !(check file:test(dir, file:EXISTS)) {
        check file:createDir(dir, file:RECURSIVE);
    }
    json src = {
        schemaVersion: 1,
        sequence: 11,
        publishedAt: "2026-09-19T00:00:00Z",
        apps: [
            {
                'version: version,
                'commit: commitSha,
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
}
