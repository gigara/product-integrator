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
public type SignatureRef record {
    string sigUrl;
    string certUrl;
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
