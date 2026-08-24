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

// Record model for the update source document described in
// docs/update-mechanism-design.md (§3). The records are intentionally OPEN so a document can gain
// forward-compatible fields without breaking validation on an older server build.
//
// The per-platform `Manifest` records that used to live here went with the endpoints that served
// them: no client has fetched a manifest by path since the server began composing responses.


// Where an artifact's signed statement and its detached signature live.
//
// `statementUrl` is a small JSON document binding the artifact's identity to its bytes
// ({id, version, sha256, sizeBytes, requires}); `sigUrl` is the detached signature over that
// document, which the client verifies against its pinned public key. Signing the statement rather
// than the bytes is what stops a manifest offering an old signed artifact under a new version label.
//
// Deliberately no `certUrl`: that belonged to the keyless-cosign model, where the signing
// certificate was fetched alongside the signature. Signing is key-based now and the client pins the
// public key, so there is no certificate to fetch.
public type StatementRef record {
    string statementUrl;
    string sigUrl;
};


// Client-side staged-rollout control. The client decides visibility with
// sha1(deviceId + componentId + version) mod 100 < percentage; the server
// never mutates the manifest, so rollout is data carried inside it.
public type Rollout record {
    int percentage;
};

// Squirrel.Mac payload reference (darwin manifests): the editor-only .app zip on the CDN.
public type SquirrelPayload record {
    string url;
};





// --- source document (schemaVersion 2) -------------------------------------------------
// ONE published document per channel describes every platform/arch. The server reads it and
// composes a per-client response; clients never see it. Keeping the fan-out here rather than in
// published files is what lets one document serve several release lines and, later, entitlement.

// One platform-arch's copy of an artifact. Keyed by "<platform>-<arch>" in a `targets` map.
public type TargetArtifact record {
    string url;
    string sha256;
    int sizeBytes;
    StatementRef signature?;
};

// A component offered across targets. `requires` and `rollout` apply to every target alike.
public type SourceComponent record {
    string id;
    string kind;
    string 'version;
    map<string> requires?;
    Rollout rollout?;
    boolean recommended?;
    string releaseNotesUrl?;
    map<TargetArtifact> targets;
};

// The core app for one platform-arch: its installer, plus the Squirrel zip where one exists.
public type AppTarget record {
    TargetArtifact installer;
    SquirrelPayload squirrel?;
};

// A core-app release. `appliesTo` is a range over the CLIENT'S CURRENT version, which is how one
// document serves several lines at once: a 5.1.z entry with ">=5.1.0 <5.2.0" simply does not match
// a 5.2.x client, so that client is never offered it.
public type SourceApp record {
    string 'version;
    string 'commit?;
    string appliesTo?;
    Rollout rollout?;
    string releaseNotesUrl?;
    map<AppTarget> targets;
};

// No channel field: a document's channel is the manifests/<channel>/ prefix it was read from, and
// promotion copies documents between channels, so a field would have to be rewritten every time.
//
// No expiry field either. An enforced one stops a maintenance line's updates on a date nobody set
// deliberately. Withdrawal is explicit: repoint the index entry, or add a `revocations` entry.
public type SourceManifest record {
    int schemaVersion;
    int sequence;
    string publishedAt;
    SourceApp[] apps;
    SourceComponent[] components;
};

// The only source-document schema. Validated on read and at publish: unchecked, an incompatible
// document would be mis-parsed into whatever the current record happens to accept.
public const int SOURCE_SCHEMA_VERSION = 1;

// --- release-line index ----------------------------------------------------------------

// One line of the index: which source document serves clients whose version matches `match`.
//
// `match` accepts an exact version (5.1.4), a wildcard (5.1.x, 5.x, or * for everything), or a
// range using the same comparators as `requires` (">=5.1.0 <5.2.0"). Entries are evaluated TOP
// TO BOTTOM and the FIRST match wins, so put the specific ones above the catch-alls — that
// ordering is the whole control surface for a hand-edited file, and "most specific wins" would
// make the outcome depend on a similarity rule nobody can see while editing.
public type IndexEntry record {
    string 'match;
    string manifest;
    string note?;
};

// A server-configured exception to the published index (see `lineOverrides` in config.bal).
//
// Field names avoid Ballerina's reserved words deliberately: these are read straight out of
// Config.toml, and `match` would have to be quoted there and in every operator's muscle memory.
public type LineOverride record {
    string clients;
    string manifest;
    string channel?;
    string note?;
};

// Maps a client's app version to the source document that serves its release line, so each release
// publishes an immutable document of its own instead of rewriting a shared one.
//
// Deliberately NOT signature-checked, unlike the documents it points at. It can only choose among
// documents that are themselves verified before use, so the worst a rewritten index can do is
// withhold updates or select an older line — both of which the server can already do, and neither
// of which puts unverified code in front of a client. Requiring a signature here would also make
// the file impossible to correct by hand, which is how it is meant to be maintained.
public type SourceIndex record {
    int schemaVersion;
    IndexEntry[] entries;
};

// --- update-check protocol -------------------------------------------------------------

// What the client reports about itself. `bucket` is the client's own 0-99 rollout slot, computed
// locally from a device id that is deliberately NEVER transmitted.
public type UpdateCheckRequest record {
    string channel?;
    string platform;
    string arch;
    string appVersion;
    string appCommit?;
    // EVERY component the client has, bundled ones included — not just installed overrides. A
    // component omitted here is treated as absent, and any other component whose `requires` names
    // it is then withheld, since the server has no way to tell "not installed" from "not reported".
    map<string> components?;
    int bucket?;
};

// One component the server decided this client should take.
public type ComponentOffer record {
    string id;
    string kind;
    string 'version;
    TargetArtifact artifact;
    map<string> requires?;
    string releaseNotesUrl?;
};

// The core-app offer, carrying whichever payload the platform applies.
public type AppOffer record {
    string 'version;
    string 'commit?;
    TargetArtifact installer;
    SquirrelPayload squirrel?;
    string releaseNotesUrl?;
};

public type UpdateCheckResponse record {
    AppOffer app?;
    ComponentOffer[] components;
    string publishedAt;
    int sequence;
};
