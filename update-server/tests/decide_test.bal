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
    schemaVersion: 1,
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
    // A pre-release ranks below its release. This previously asserted 0 — "suffixes deliberately
    // ignored" — which is what stranded pre-release clients: the release never compared as newer,
    // so it was never offered. See testVersionComparisonMatchesTheClient for the full contract.
    test:assertEquals(compareVersions("5.1.2-testalpha1", "5.1.2"), -1);
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
    schemaVersion: 1,
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

// --- release-line index ---------------------------------------------------------------

@test:Config {}
function testSelectorFormsMatchTheRightVersions() {
    // Exact.
    test:assertTrue(matchesSelector("5.1.4", "5.1.4"));
    test:assertFalse(matchesSelector("5.1.5", "5.1.4"));
    // Wildcard: the segments before it must match, everything after is free.
    test:assertTrue(matchesSelector("5.1.0", "5.1.x"));
    test:assertTrue(matchesSelector("5.1.4", "5.1.x"));
    test:assertFalse(matchesSelector("5.2.0", "5.1.x"));
    test:assertTrue(matchesSelector("5.9.9", "5.x"));
    test:assertFalse(matchesSelector("6.0.0", "5.x"));
    // A pre-release belongs to its own line: 5.1.4-beta is still 5.1.x, not 5.2.x.
    test:assertTrue(matchesSelector("5.1.4-beta", "5.1.x"));
    test:assertFalse(matchesSelector("5.2.0-alpha", "5.1.x"));
    // Range.
    test:assertTrue(matchesSelector("5.1.4", ">=5.1.0 <5.2.0"));
    test:assertFalse(matchesSelector("5.2.1", ">=5.1.0 <5.2.0"));
    // Catch-all.
    test:assertTrue(matchesSelector("7.0.0", "*"));
    // A wildcard must not be read as a range comparison against the literal "5.1.x",
    // which is what happens if the wildcard branch is checked after the range branch.
    test:assertFalse(matchesSelector("9.9.9", "5.1.x"));
}

@test:Config {}
function testIndexSelectsFirstMatchAndNothingWhenUncovered() {
    SourceIndex index = {
        schemaVersion: 1,
        entries: [
            {'match: "5.1.4", manifest: "source-5.1.4-hotfix.json"},
            {'match: "5.1.x", manifest: "source-5.1.5.json"},
            {'match: ">=5.2.0 <5.3.0", manifest: "source-5.2.1.json"}
        ]
    };
    // First match wins: the pinned 5.1.4 entry beats the 5.1.x line entry below it.
    test:assertEquals(selectManifest(index, "5.1.4"), "source-5.1.4-hotfix.json");
    test:assertEquals(selectManifest(index, "5.1.5"), "source-5.1.5.json");
    test:assertEquals(selectManifest(index, "5.2.1"), "source-5.2.1.json");
    // A line the index does not cover gets nothing rather than a guess.
    test:assertEquals(selectManifest(index, "4.9.0"), ());
    // A client that reports no version at all is only served by a catch-all entry.
    test:assertEquals(selectManifest(index, ()), ());
    SourceIndex withCatchAll = {
        schemaVersion: 1,
        entries: [{'match: "5.1.x", manifest: "a.json"}, {'match: "*", manifest: "fallback.json"}]
    };
    test:assertEquals(selectManifest(withCatchAll, ()), "fallback.json");
    test:assertEquals(selectManifest(withCatchAll, "9.0.0"), "fallback.json");
}

@test:Config {}
function testSourceFileNamesRejectTraversal() {
    test:assertTrue(isSourceFile("source.json"));
    test:assertTrue(isSourceFile("index.json"));
    test:assertTrue(isSourceFile("source-5.2.1.json"));
    test:assertTrue(isSourceFile("source-5.2.1.json.sig"));
    test:assertTrue(isSourceFile("source-5.1.4-testalpha1.json"));
    // A hand-edited index must not be able to reach outside the channel prefix.
    test:assertFalse(isSourceFile("../../etc/passwd"));
    test:assertFalse(isSourceFile("source-../../evil.json"));
    test:assertFalse(isSourceFile("a/b.json"));
    test:assertFalse(isSourceFile("source-5.2.1.txt"));
    test:assertFalse(isSourceFile("manifest.json"));
}

@test:Config {}
function testLineOverrideMatchingIsChannelScopedAndOrdered() {
    // lineOverrides is `configurable`, so the test drives the matching directly rather than the
    // deployment value: what matters is the selection rule, not what any one deployment configures.
    LineOverride[] configured = [
        {clients: "5.1.4", manifest: "source-pinned.json"},
        {clients: "5.1.x", manifest: "source-5.3.0.json", note: "5.1 EOL"},
        {clients: "5.2.x", manifest: "source-beta-only.json", channel: "beta"}
    ];
    // First match wins, so the pin above the wildcard is reachable.
    test:assertEquals(pickOverride(configured, "stable", "5.1.4"), "source-pinned.json");
    test:assertEquals(pickOverride(configured, "stable", "5.1.5"), "source-5.3.0.json");
    // A channel-scoped entry applies only to that channel.
    test:assertEquals(pickOverride(configured, "beta", "5.2.0"), "source-beta-only.json");
    test:assertEquals(pickOverride(configured, "stable", "5.2.0"), ());
    // Matching nothing falls through to the index rather than withholding everything.
    test:assertEquals(pickOverride(configured, "stable", "9.9.9"), ());
    // A client that reports no version is only claimed by an unconstrained entry.
    test:assertEquals(pickOverride(configured, "stable", ()), ());
    test:assertEquals(pickOverride([{clients: "*", manifest: "all.json"}], "stable", ()), "all.json");
}

// Parity with the CLIENT's compareVersions (wso2ComponentsManifest.ts). Every expectation here was
// produced by running the vector through the real client implementation — if the two ever diverge,
// the server offers updates the client refuses, and a user sees a check that finds something and
// then does nothing. Keep both sides in step or delete neither.
@test:Config {}
function testVersionComparisonMatchesTheClient() {
    [string, string, int][] vectors = [
        ["5.1.3-testalpha1", "5.1.3", -1],          // a pre-release ranks below its release
        ["5.1.3", "5.1.3-testalpha1", 1],
        ["5.1.3-testalpha1", "5.1.3-testalpha1", 0],
        ["5.1.3-testalpha1", "5.1.3-testalpha2", -1],
        ["2201.13.6-alpha2", "2201.13.6", -1],
        ["2201.13.6-Alpha", "2201.13.6-alpha2", -1], // ASCII order: uppercase sorts first
        ["2201.13.4", "2201.13.5", -1],
        ["5.0.0.1", "5.0.0.2", -1],                  // 4-part versions
        ["5.0.0.1", "5.0.0", 1],
        ["5.12.4", "5.13.26081016", -1],
        ["1.0.0-alpha", "1.0.0-alpha.1", -1],        // fewer identifiers rank lower
        ["1.0.0-alpha.1", "1.0.0-alpha.beta", -1],   // numeric ranks below alphanumeric
        ["1.0.0-beta", "1.0.0-beta.2", -1],
        ["1.0.0-beta.2", "1.0.0-beta.11", -1],       // numeric, not lexical: 2 < 11
        ["1.0.0-rc.1", "1.0.0", -1],
        ["5.1.3+build9", "5.1.3", 0],                // build metadata is ignored
        ["5.1.0", "5.1", 0]                          // missing segments are zero
    ];
    foreach [string, string, int] [a, b, want] in vectors {
        test:assertEquals(compareVersions(a, b), want, string `compareVersions(${a}, ${b})`);
        // Antisymmetry: whichever way round it is asked, the answer must invert.
        test:assertEquals(compareVersions(b, a), -want, string `compareVersions(${b}, ${a})`);
    }
}
