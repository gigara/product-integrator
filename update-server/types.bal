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

// Record model for the update manifest described in
// docs/update-mechanism-design.md (§4.2). The records are intentionally OPEN
// so that manifests can gain forward-compatible fields without breaking
// validation on older server builds. The server serves the manifest bytes
// verbatim (to preserve the detached signature); these types are used for
// admin-publish validation, tests, and documentation of the contract.

// A detached-signature reference (cosign sign-blob output locations).
// LEGACY: used only by the per-platform `Manifest` below, which the client no longer fetches.
// New work belongs on `StatementRef`; this stays as-is so the retired fixtures still describe what
// that endpoint actually served (keyless cosign, signature + signing certificate).
public type SignatureRef record {
    string sigUrl;
    string certUrl;
};

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

// A downloadable artifact with integrity metadata.
public type Artifact record {
    string url;
    string sha256;
    int sizeBytes;
    SignatureRef signature?;
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

// The core-app update entry (full installer per platform/arch). `commit` is the
// product-integrator root sha the build was produced from — the Squirrel endpoint
// compares the mac client's commit against it. `squirrel` is present on darwin
// manifests only.
public type AppUpdate record {
    string 'version;
    string minAutoUpdateFromVersion?;
    Artifact installer;
    string releaseNotesUrl?;
    Rollout rollout?;
    string 'commit?;
    SquirrelPayload squirrel?;
};

// An independently updatable component (extension | runtime | app).
public type Component record {
    string id;
    string kind;
    string 'version;
    Artifact artifact;
    // component-id (or "app") -> semver range that must be satisfied.
    map<string> requires?;
    string releaseNotesUrl?;
    Rollout rollout?;
};

// The tested release train the client offers as a single bundle by default.
public type RecommendedSet record {
    string name;
    map<string> members;
};

// The full manifest served per (channel, platform, arch).
public type Manifest record {
    int schemaVersion;
    string channel;
    string platform;
    string arch;
    int sequence;
    string publishedAt;
    string expiresAt?;
    AppUpdate app?;
    Component[] components;
    RecommendedSet recommendedSet?;
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

public type SourceManifest record {
    int schemaVersion;
    string channel;
    int sequence;
    string publishedAt;
    string expiresAt?;
    SourceApp[] apps;
    SourceComponent[] components;
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
    string checkedAt;
    int sequence;
};
