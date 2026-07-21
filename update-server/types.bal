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

// The core-app update entry (full installer per platform/arch).
public type AppUpdate record {
    string 'version;
    string minAutoUpdateFromVersion?;
    Artifact installer;
    string releaseNotesUrl?;
    Rollout rollout?;
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
