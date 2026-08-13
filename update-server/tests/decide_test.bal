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

import ballerina/test;

function sampleSource() returns SourceManifest => {
    schemaVersion: 2,
    channel: "stable",
    sequence: 10,
    publishedAt: "2026-08-13T00:00:00Z",
    apps: [
        {
            'version: "5.1.9",
            'commit: "sha519",
            appliesTo: ">=5.1.0 <5.2.0",
            targets: {
                "darwin-arm64": {
                    installer: {url: "https://cdn/app/5.1.9/x.dmg", sha256: "a", sizeBytes: 1},
                    squirrel: {url: "https://cdn/app/5.1.9/x-mac.zip"}
                },
                "win32-x64": {installer: {url: "https://cdn/app/5.1.9/x.msi", sha256: "b", sizeBytes: 2}}
            }
        },
        {
            'version: "5.2.3",
            'commit: "sha523",
            appliesTo: ">=5.2.0 <5.3.0",
            targets: {"darwin-arm64": {installer: {url: "https://cdn/app/5.2.3/x.dmg", sha256: "c", sizeBytes: 3}}}
        }
    ],
    components: [
        {
            id: "ballerina-runtime",
            kind: "runtime",
            'version: "2201.13.5",
            requires: {"app": ">=5.1.0", "jre": ">=3.0.2"},
            targets: {
                "darwin-arm64": {url: "https://cdn/c/bal-mac-arm.zip", sha256: "d", sizeBytes: 4},
                "win32-x64": {url: "https://cdn/c/bal-win.zip", sha256: "e", sizeBytes: 5}
            }
        },
        {
            id: "jre",
            kind: "runtime",
            'version: "3.0.2",
            targets: {"darwin-arm64": {url: "https://cdn/c/jre-mac.zip", sha256: "f", sizeBytes: 6}}
        },
        {
            id: "wso2.ballerina",
            kind: "extension",
            'version: "5.13.0",
            requires: {"app": ">=5.2.0"},
            targets: {"darwin-arm64": {url: "https://cdn/c/bal.vsix", sha256: "g", sizeBytes: 7}}
        },
        {
            id: "canary",
            kind: "extension",
            'version: "2.0.0",
            rollout: {percentage: 10},
            targets: {"darwin-arm64": {url: "https://cdn/c/canary.vsix", sha256: "h", sizeBytes: 8}}
        }
    ]
};

function offeredIds(UpdateCheckResponse? r) returns string[] {
    if r is () {
        return [];
    }
    return from ComponentOffer c in r.components
        select c.id;
}

@test:Config {}
function testOffersOnlyWhatThePlatformHas() {
    // The client reports EVERY component it has, bundled ones included — an unreported dependency
    // fails the requires gate closed (jre is needed by ballerina-runtime but is not published for
    // win32, so it can only come from what the client reports).
    UpdateCheckResponse? r = decideUpdates(sampleSource(), {
        platform: "win32", arch: "x64", appVersion: "5.1.9",
        components: {"ballerina-runtime": "2201.13.4", "jre": "3.0.2"}
    });
    // jre / wso2.ballerina / canary publish nothing for win32-x64, so only the runtime is offered.
    test:assertEquals(offeredIds(r), ["ballerina-runtime"]);
}

@test:Config {}
function testSkipsComponentsAlreadyCurrentOrNewer() {
    // appVersion is the newest of its line so no app offer clouds the component assertion.
    UpdateCheckResponse? r = decideUpdates(sampleSource(), {
        platform: "win32", arch: "x64", appVersion: "5.1.9",
        components: {"ballerina-runtime": "2201.13.5", "jre": "3.0.2"}
    });
    test:assertEquals(r, ());
    UpdateCheckResponse? newer = decideUpdates(sampleSource(), {
        platform: "win32", arch: "x64", appVersion: "5.1.9",
        components: {"ballerina-runtime": "2201.14.0", "jre": "3.0.2"}
    });
    test:assertEquals(newer, ());
}

@test:Config {}
function testRequiresGateUsesTheClientsCurrentAppVersion() {
    // wso2.ballerina needs app >= 5.2.0, so a 5.1.x client must not be offered it even though the
    // same response offers that client an app update to 5.1.9.
    UpdateCheckResponse? onFiveOne = decideUpdates(sampleSource(), {
        platform: "darwin", arch: "arm64", appVersion: "5.1.0", components: {}
    });
    test:assertFalse(offeredIds(onFiveOne).indexOf("wso2.ballerina") is int);

    UpdateCheckResponse? onFiveTwo = decideUpdates(sampleSource(), {
        platform: "darwin", arch: "arm64", appVersion: "5.2.0", components: {}
    });
    test:assertTrue(offeredIds(onFiveTwo).indexOf("wso2.ballerina") is int);
}

@test:Config {}
function testAppLineSeparation() {
    // One document, two lines: each client is offered its own line's release and never the other's.
    UpdateCheckResponse? five1 = decideUpdates(sampleSource(), {
        platform: "darwin", arch: "arm64", appVersion: "5.1.2", components: {}
    });
    AppOffer? a1 = five1 is () ? () : five1?.app;
    test:assertEquals(a1 is AppOffer ? a1.'version : "none", "5.1.9");

    UpdateCheckResponse? five2 = decideUpdates(sampleSource(), {
        platform: "darwin", arch: "arm64", appVersion: "5.2.0", components: {}
    });
    AppOffer? a2 = five2 is () ? () : five2?.app;
    test:assertEquals(a2 is AppOffer ? a2.'version : "none", "5.2.3");

    // A client already on the newest of its line gets no app offer.
    UpdateCheckResponse? current = decideUpdates(sampleSource(), {
        platform: "darwin", arch: "arm64", appVersion: "5.1.9", components: {"jre": "3.0.2"}
    });
    AppOffer? a3 = current is () ? () : current?.app;
    test:assertTrue(a3 is ());
}

@test:Config {}
function testSquirrelPayloadTravelsOnlyWhereItExists() {
    UpdateCheckResponse? mac = decideUpdates(sampleSource(), {
        platform: "darwin", arch: "arm64", appVersion: "5.1.2", components: {}
    });
    AppOffer? macApp = mac is () ? () : mac?.app;
    test:assertTrue(macApp is AppOffer && macApp?.squirrel is SquirrelPayload);

    UpdateCheckResponse? win = decideUpdates(sampleSource(), {
        platform: "win32", arch: "x64", appVersion: "5.1.2", components: {"ballerina-runtime": "2201.13.5"}
    });
    AppOffer? winApp = win is () ? () : win?.app;
    test:assertTrue(winApp is AppOffer && winApp?.squirrel is ());
}

@test:Config {}
function testRolloutNeedsAReportedBucket() {
    // Inside the canary slice.
    UpdateCheckResponse? inSlice = decideUpdates(sampleSource(), {
        platform: "darwin", arch: "arm64", appVersion: "5.2.0", components: {}, bucket: 5
    });
    test:assertTrue(offeredIds(inSlice).indexOf("canary") is int);

    // Outside it.
    UpdateCheckResponse? outside = decideUpdates(sampleSource(), {
        platform: "darwin", arch: "arm64", appVersion: "5.2.0", components: {}, bucket: 50
    });
    test:assertFalse(offeredIds(outside).indexOf("canary") is int);

    // No bucket reported: held back rather than waved through, so a hand-made request cannot opt
    // itself into a canary.
    UpdateCheckResponse? noBucket = decideUpdates(sampleSource(), {
        platform: "darwin", arch: "arm64", appVersion: "5.2.0", components: {}
    });
    test:assertFalse(offeredIds(noBucket).indexOf("canary") is int);
}

@test:Config {}
function testUnknownComponentIsOfferedAndNothingMeansNoContent() {
    // A component the client never mentions is one it does not have.
    UpdateCheckResponse? r = decideUpdates(sampleSource(), {
        platform: "darwin", arch: "arm64", appVersion: "5.1.9", components: {}
    });
    test:assertTrue(offeredIds(r).indexOf("jre") is int);

    // Fully up to date on its line and on every component it can see -> ().
    UpdateCheckResponse? none = decideUpdates(sampleSource(), {
        platform: "darwin", arch: "arm64", appVersion: "5.1.9",
        components: {"ballerina-runtime": "2201.13.5", "jre": "3.0.2", "wso2.ballerina": "5.13.0", "canary": "2.0.0"}
    });
    test:assertEquals(none, ());
}

@test:Config {}
function testVersionComparisonAndRanges() {
    test:assertEquals(compareVersions("2201.13.5", "2201.13.4"), 1);
    test:assertEquals(compareVersions("5.0.0.2", "5.0.0.1"), 1);
    test:assertEquals(compareVersions("5.1.2", "5.1.2"), 0);
    test:assertEquals(compareVersions("5.1.2-testalpha1", "5.1.2"), 0); // suffixes deliberately ignored, as on the client
    test:assertTrue(satisfiesRange("5.1.5", ">=5.1.0 <5.2.0"));
    test:assertFalse(satisfiesRange("5.2.0", ">=5.1.0 <5.2.0"));
    test:assertTrue(satisfiesRange("3.0.2", ">=3.0.2"));
    test:assertTrue(satisfiesRange("5.1.0", ""));
}

@test:Config {}
function testSquirrelPicksTheClientsLineAndOnlyWhereAPayloadExists() {
    SourceManifest src = sampleSource();
    // A 5.1.x client is matched to the 5.1 entry, which is the one carrying a Squirrel payload.
    SourceApp? five1 = decideSquirrel(src, "darwin-arm64", "5.1.2");
    test:assertEquals(five1 is SourceApp ? five1.'version : "none", "5.1.9");

    // A 5.2.x client is matched to the 5.2 entry — which publishes no Squirrel payload, so the feed
    // has nothing for it rather than falling back to the other line's zip.
    SourceApp? five2 = decideSquirrel(src, "darwin-arm64", "5.2.0");
    test:assertTrue(five2 is (), "5.2 entry has no squirrel payload, so nothing may be offered");

    // A client that predates `wiversion` reports no version: it cannot be placed on a line, so the
    // newest entry that has a payload is used rather than stranding it with no updates at all.
    SourceApp? legacy = decideSquirrel(src, "darwin-arm64", ());
    test:assertEquals(legacy is SourceApp ? legacy.'version : "none", "5.1.9");

    // win32 publishes an installer but never a Squirrel payload.
    test:assertTrue(decideSquirrel(src, "win32-x64", "5.1.2") is ());
}

// --- per-line component entries (one document, two release lines) ---------------------------

// wso2.ballerina ships twice: 5.12.x for the 5.1 line, 5.13.x for 5.2. A third component depends on
// it, so this also pins down WHICH version a dependency is resolved against.
function multiLineSource() returns SourceManifest => {
    schemaVersion: 2,
    channel: "stable",
    sequence: 20,
    publishedAt: "2026-08-13T00:00:00Z",
    apps: [],
    components: [
        {
            id: "wso2.ballerina",
            kind: "extension",
            'version: "5.12.4",
            requires: {"app": ">=5.1.0 <5.2.0"},
            targets: {"darwin-arm64": {url: "https://cdn/bal-5.12.4.vsix", sha256: "a", sizeBytes: 1}}
        },
        {
            id: "wso2.ballerina",
            kind: "extension",
            'version: "5.13.1",
            requires: {"app": ">=5.2.0"},
            targets: {"darwin-arm64": {url: "https://cdn/bal-5.13.1.vsix", sha256: "b", sizeBytes: 2}}
        },
        {
            id: "companion",
            kind: "extension",
            'version: "1.0.0",
            requires: {"wso2.ballerina": ">=5.13.0"},
            targets: {"darwin-arm64": {url: "https://cdn/companion.vsix", sha256: "c", sizeBytes: 3}}
        }
    ]
};

function offeredVersion(UpdateCheckResponse? r, string id) returns string {
    if r is () {
        return "none";
    }
    foreach ComponentOffer c in r.components {
        if c.id == id {
            return c.'version;
        }
    }
    return "none";
}

function offerCount(UpdateCheckResponse? r, string id) returns int {
    if r is () {
        return 0;
    }
    int count = 0;
    foreach ComponentOffer c in r.components {
        if c.id == id {
            count += 1;
        }
    }
    return count;
}

@test:Config {}
function testEachLineGetsItsOwnComponentVersion() {
    UpdateCheckResponse? five1 = decideUpdates(multiLineSource(), {
        platform: "darwin", arch: "arm64", appVersion: "5.1.4", components: {"wso2.ballerina": "5.12.0"}
    });
    test:assertEquals(offeredVersion(five1, "wso2.ballerina"), "5.12.4");

    UpdateCheckResponse? five2 = decideUpdates(multiLineSource(), {
        platform: "darwin", arch: "arm64", appVersion: "5.2.1", components: {"wso2.ballerina": "5.12.0"}
    });
    test:assertEquals(offeredVersion(five2, "wso2.ballerina"), "5.13.1");
}

@test:Config {}
function testAComponentIsNeverOfferedTwice() {
    UpdateCheckResponse? r = decideUpdates(multiLineSource(), {
        platform: "darwin", arch: "arm64", appVersion: "5.2.1", components: {}
    });
    test:assertEquals(offerCount(r, "wso2.ballerina"), 1, "per-line entries must collapse to one offer per component id");
}

@test:Config {}
function testDependenciesResolveAgainstTheClientsOwnLine() {
    // `companion` needs wso2.ballerina >= 5.13.0. A 5.2 client projects 5.13.1 and qualifies.
    UpdateCheckResponse? five2 = decideUpdates(multiLineSource(), {
        platform: "darwin", arch: "arm64", appVersion: "5.2.1", components: {}
    });
    test:assertEquals(offeredVersion(five2, "companion"), "1.0.0");

    // A 5.1 client projects 5.12.4 and must NOT qualify — before the fix it was evaluated against
    // 5.13.1, a version that client can never be given.
    UpdateCheckResponse? five1 = decideUpdates(multiLineSource(), {
        platform: "darwin", arch: "arm64", appVersion: "5.1.4", components: {}
    });
    test:assertEquals(offeredVersion(five1, "companion"), "none");
}
