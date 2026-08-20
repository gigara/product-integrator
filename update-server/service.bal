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

// HTTP service for the WSO2 Integrator component-wise update mechanism.
//
// Implements the read API from docs/update-mechanism-design.md (§4.1):
//
//   GET /api/v1/updates/{channel}/{platform}/{arch}/manifest.json      (+ .sig, .pem)
//
// The server serves the published manifest bytes VERBATIM so the detached
// cosign signature stays valid; it never rewrites the manifest. Staged rollout
// and compatibility resolution are performed client-side against the manifest
// data. A token-guarded admin publish endpoint is provided for CI/testing.

import ballerina/crypto;
import ballerina/file;
import ballerina/http;
import ballerina/lang.array;
import ballerina/log;

// Refuse to start rather than run permissively. `check` here fails module init, so the server does
// not come up at all when verification is neither configured nor explicitly waived.
final boolean sourceTrustConfigured = check requireSourceTrust();

isolated function requireSourceTrust() returns boolean|error {
    if sourcePublicKey != "" {
        return true;
    }
    if allowUnsignedSource {
        log:printWarn("source document signature verification is DISABLED (allowUnsignedSource = true); "
                + "every document this server reads is trusted unverified");
        return false;
    }
    return error("sourcePublicKey is not configured. The server verifies each source document's "
            + "signature before trusting it; without a key it would trust whatever it fetches. Set "
            + "sourcePublicKey (base64 of cosign.pub), or set allowUnsignedSource = true to run "
            + "without verification deliberately.");
}

listener http:Listener updateListener = new (port);

service / on updateListener {

    // Liveness/readiness probe.
    resource function get healthz() returns json {
        return {status: "ok", 'service: "wso2-integrator-update-server"};
    }

    // Lists the channels that currently have published content. In S3 mode the
    // configured channel allowlist is returned as-is (informational; probing the
    // bucket per channel on every call would defeat the read cache).
    resource function get api/v1/channels() returns http:Response {
        // Any remote store: the configured allowlist is the answer. Probing a bucket or CDN per
        // channel on every call would defeat the read cache — and reporting an empty list because
        // the LOCAL directory is empty (which it always is in a remote mode) reads as "nothing is
        // published", which is exactly the wrong thing to tell someone debugging a quiet server.
        if s3Bucket != "" || manifestsBaseUrl != "" {
            return jsonResponse(200, {channels: allowedChannels.toJson()});
        }
        string[] available = [];
        do {
            foreach string channel in allowedChannels {
                string channelDir = check file:joinPath(dataDir, "api", "v1", "updates", channel);
                boolean exists = check file:test(channelDir, file:EXISTS);
                if exists {
                    available.push(channel);
                }
            }
            return jsonResponse(200, {channels: available});
        } on fail error e {
            log:printError("failed to list channels", e);
            return jsonResponse(500, {'error: "internal error"});
        }
    }

    // Squirrel.Mac core-app update feed (macOS). Electron's autoUpdater polls
    //   GET /api/update/{darwin|darwin-arm64}/{quality}/{commit}
    // and expects 200 {url, ...} when a newer build exists, or 204 when current.
    // Derived from the channel's (cosign-signed) manifest itself: the darwin manifest
    // carries `app.commit` (the product-integrator root sha the build was produced
    // from) and `app.squirrel.url` (the editor-only .app zip on the CDN) — no separate
    // feed artifact. Every failure path deliberately degrades to 204 ("no update") —
    // a broken/missing manifest must never surface an error on each mac client's check.
    resource function get api/update/[string assetId]/[string quality]/[string clientCommit](
            http:Request request, string? wiversion) returns http:Response {
        http:Response? denied = clientAuthGuard(request);
        if denied is http:Response {
            return denied;
        }
        string? arch = assetId == "darwin" ? "x64" : assetId == "darwin-arm64" ? "arm64" : ();
        if arch is () {
            return jsonResponse(404, {'error: "unsupported asset"});
        }
        http:Response noUpdate = new;
        noUpdate.statusCode = 204;
        noUpdate.setHeader("Cache-Control", "no-store");
        recordCheck(quality, assetId, arch, wiversion);
        // Kill-switch applies to the mac core app exactly like the component manifest.
        if isRevoked(quality, "darwin", arch) {
            log:printInfo(string `squirrel feed withheld (revoked) quality=${quality} arch=${arch}`);
            return noUpdate;
        }
        do {
            SourceManifest? src = check loadSource(quality, wiversion);
            if src is () {
                return noUpdate; // nothing published for this channel
            }
            boolean viaOverride = check overrideApplies(quality, wiversion);
            SourceApp? app = decideSquirrel(src, string `darwin-${arch}`, wiversion, viaOverride);
            if app is () {
                return noUpdate; // no Squirrel payload for this target/line
            }
            string? feedCommit = app?.'commit;
            if feedCommit is () {
                return noUpdate; // document predates commit-stamped app entries
            }
            if feedCommit == clientCommit {
                return noUpdate; // client already runs the latest published build
            }
            // Belt and braces alongside `appliesTo`: a document that omits the range is still held
            // to the client's own line, so a cross-line build cannot reach it by accident.
            //
            // An operator override is exempt. Its entire purpose is to send a line somewhere it
            // would not go on its own — moving an end-of-life 5.1.x onto 5.3, say — and a guard
            // against ACCIDENTAL crossings must not veto a deliberate one, or the override would
            // appear to work everywhere except macOS.
            if restrictAppUpdatesToMinorLine && !viaOverride && wiversion is string {
                string? clientLine = minorLine(wiversion);
                string? targetLine = minorLine(app.'version);
                if clientLine is string && targetLine is string && clientLine != targetLine {
                    log:printInfo(string `squirrel update withheld (minor line) client=${wiversion} target=${app.'version}`);
                    return noUpdate;
                }
            }
            AppTarget chosen = <AppTarget>app.targets[string `darwin-${arch}`];
            SquirrelPayload squirrel = <SquirrelPayload>chosen?.squirrel;
            log:printInfo(string `squirrel update offered quality=${quality} arch=${arch} version=${app.'version} to commit=${clientCommit}`);
            return jsonResponse(200, {
                url: squirrel.url,
                name: app.'version,
                productVersion: app.'version,
                pub_date: src.publishedAt
            });
        } on fail error e {
            log:printError("squirrel feed lookup failed", e);
            return noUpdate;
        }
    }

    // Admin: list current kill-switch revocations. Bearer adminToken; 404 when disabled.
    // The update check. The client reports what it has; the server decides what it should take.
    //
    // 204 means "nothing for you" and is also every failure mode: a broken or unpublished channel
    // must degrade to "no updates", never to an error the client surfaces to a user who cannot act
    // on it.
    resource function post api/v1/updates(http:Request request, @http:Payload UpdateCheckRequest body)
            returns http:Response {
        http:Response? denied = clientAuthGuard(request);
        if denied is http:Response {
            return denied;
        }
        string channel = body?.channel ?: "stable";
        http:Response nothing = new;
        nothing.statusCode = 204;
        nothing.setHeader("Cache-Control", "no-store");

        recordCheck(channel, body.platform, body.arch, body.appVersion);
        // Kill-switch: withhold everything for a revoked scope so NEW clients take nothing, without
        // rewriting or re-signing a thing.
        if isRevoked(channel, body.platform, body.arch) {
            log:printInfo(string `updates withheld (revoked) channel=${channel} platform=${body.platform} arch=${body.arch}`);
            return nothing;
        }
        do {
            SourceManifest? src = check loadSource(channel, body.appVersion);
            if src is () {
                return nothing;
            }
            boolean viaOverride = check overrideApplies(channel, body.appVersion);
            UpdateCheckResponse? decision = decideUpdates(src, body, viaOverride);
            if decision is () {
                return nothing;
            }
            log:printInfo(string `offering ${decision.components.length()} component(s)` +
                string ` app=${decision?.app is AppOffer ? "yes" : "no"}` +
                string ` to ${body.platform}-${body.arch} appVersion=${body.appVersion} channel=${channel}`);
            return jsonResponse(200, decision.toJson());
        } on fail error e {
            log:printError("update check failed", e);
            return nothing;
        }
    }

    // Admin: what this deployment is currently withholding. READ ONLY — revocations are deployment
    // configuration now, so they change by redeploying, not by calling an endpoint. Kept because
    // "what is being withheld right now, and why" is the first question during an incident, and
    // reading it back from the running server beats trusting that the config you are looking at is
    // the config that is deployed.
    resource function get api/v1/admin/revocations(http:Request request) returns http:Response {
        http:Response? denied = authGuard(request);
        if denied is http:Response {
            return denied;
        }
        return jsonResponse(200, {revocations: revocations.toJson()});
    }

    // Admin: in-memory update-check counters (per scope and per appVersion). Bearer adminToken.
    resource function get api/v1/admin/metrics(http:Request request) returns http:Response {
        http:Response? denied = authGuard(request);
        if denied is http:Response {
            return denied;
        }
        return jsonResponse(200, {checks: metricsSnapshot().toJson()});
    }

    // Admin publish of a source-layout file: a release's document, its signature, or the index.
    //
    // NOT the path CI uses. A release writes to the bucket directly with `aws s3 cp`, so this
    // endpoint exists for a deployment with NO bucket configured, where the local data directory is
    // the only store and nothing else can put a document there.
    //
    // With a bucket configured it still write-throughs to it, which makes it a second way into the
    // store that bypasses CI. That is bounded rather than free: once `sourcePublicKey` is set the
    // server verifies the signature before trusting a document, so the worst this allows is
    // replaying an older validly-signed one, not introducing a forged one. A production deployment
    // that wants CI to be the only writer simply leaves `adminToken` unset, which disables this
    // endpoint entirely.
    //
    // Disabled (404, not 401) unless `adminToken` is configured, so an unconfigured deployment does
    // not advertise that the endpoint is there. Requires `Authorization: Bearer <token>`.
    //
    // The body is read explicitly rather than declared as `@http:Payload byte[]`: the publisher
    // sends the document as application/json (and its signature as text/plain), and data binding
    // rejects both of those against byte[] before the resource ever runs. The signature must also
    // survive byte-for-byte, so it is never round-tripped as JSON.
    resource function put api/v1/updates/[string channel]/[string fileName](http:Request request)
            returns http:Response {
        http:Response? denied = authGuard(request);
        if denied is http:Response {
            return denied;
        }
        do {
            byte[] body = check request.getBinaryPayload();
            // Any source document, not just the historical "source.json": releases publish
            // source-<version>.json, so a check pinned to the old name validated nothing.
            // Signatures and the index are not documents and have no shape to check.
            if fileName.startsWith("source") && fileName.endsWith(".json") {
                // Reject a malformed document at publish time. Otherwise the failure surfaces
                // later, on every client's update check, against a server that looks healthy.
                string text = check string:fromBytes(body);
                json parsed = check text.fromJsonString();
                SourceManifest shape = check parsed.cloneWithType(SourceManifest);
                if shape.schemaVersion != SOURCE_SCHEMA_VERSION {
                    // `fail`, not `return`: this resource returns http:Response, and the on-fail
                    // clause below is what turns an error into the 400.
                    fail error(string `document declares schemaVersion ${shape.schemaVersion}, `
                        + string `but this server only understands ${SOURCE_SCHEMA_VERSION}.`);
                }
            }
            check writeSourceManifest(channel, fileName, body);
            log:printInfo(string `published ${channel}/${fileName} (${body.length()} bytes)`);
            return jsonResponse(201, {status: "published", path: string `${channel}/${fileName}`});
        } on fail error e {
            log:printError("source publish failed", e);
            return jsonResponse(400, {'error: e.message()});
        }
    }
}


// Admin authorization guard. Returns a denial response (404 when the admin API is disabled,
// 401 on a bad/absent token) or () when the caller is authorized. Tokens are compared via
// their SHA-256 digests so the comparison leaks no prefix-timing information.
// Loads, VERIFIES and parses the channel's source document. Returns () when nothing is published.
//
// The signature is checked over the exact bytes read, before parsing: the server composes every
// client's response from this document, so accepting an unverified one would let whoever can write
// to the bucket decide what every client is offered.
// Resolves the document for a client's release line, then loads and verifies it.
//
// Each release publishes its own immutable document and adds a line to index.json, so a 5.2
// release cannot overwrite the document 5.1.x clients are still served from. When no index is
// published the single `source.json` layout is used unchanged, which is what existing deployments
// and the tests run on.
//
// A client whose version matches no index entry gets NOTHING, deliberately: guessing a line for it
// would mean offering a build from a line we were never asked to serve it.
function loadSource(string channel, string? clientVersion = ()) returns SourceManifest|error? {
    [string, boolean] [fileName, _] = check resolveSourceFileName(channel, clientVersion);
    if fileName == "" {
        return ();
    }
    [byte[], string]|error? stored = readSourceManifest(channel, fileName);
    if stored is error {
        return stored;
    }
    if stored is () {
        return ();
    }
    check verifySource(channel, fileName, stored[0]);
    string text = check string:fromBytes(stored[0]);
    json parsed = check text.fromJsonString();
    SourceManifest src = check parsed.cloneWithType(SourceManifest);
    // Refuse a schema this build does not know rather than serving whatever the current record
    // happens to accept. Ballerina's open records would silently drop fields a newer document
    // depends on, so the failure would be a WRONG offer, not a rejected one.
    if src.schemaVersion != SOURCE_SCHEMA_VERSION {
        return error(string `${channel}/${fileName} declares schemaVersion ${src.schemaVersion}, `
            + string `but this server only understands ${SOURCE_SCHEMA_VERSION}.`);
    }
    return src;
}

// The document name for this client, plus whether an operator override chose it.
//
// Two layers, checked in order:
//   overrides.json — operator-maintained, wins outright. Nothing writes it automatically, so an
//                    entry here is always a deliberate act: repointing a line at an older document
//                    after a bad release, or moving an end-of-life line onto a newer one.
//   index.json     — the table each release updates as it publishes.
//
// Returns "" when a layer exists but covers no line this client belongs to, which is served as
// "no updates" rather than a guess at which line the client should be on.
function resolveSourceFileName(string channel, string? clientVersion) returns [string, boolean]|error {
    // Server-configured exceptions win outright; matching none of them falls through to the index.
    string? overridden = lineOverrideFor(channel, clientVersion);
    if overridden is string {
        if !isSourceFile(overridden) {
            // Configuration, not a missing file: say so rather than turning it into a store lookup
            // for whatever was typed.
            return error(string `lineOverrides names an invalid manifest file: ${overridden}`);
        }
        log:printInfo(string `line override selected ${overridden} for client ${clientVersion ?: "<none>"}`);
        return [overridden, true];
    }
    string? selected = check readSelector(channel, "index.json", clientVersion);
    if selected is () {
        return ["source.json", false]; // no index published: single-document layout
    }
    if selected == "" {
        log:printInfo(string `no index entry matches client version ${clientVersion ?: "<none>"}`);
    }
    return [selected, false];
}

// Whether a configured override picked this client's document, which marks the crossing as
// deliberate for the guards that would otherwise refuse it.
function overrideApplies(string channel, string? clientVersion) returns boolean|error {
    return lineOverrideFor(channel, clientVersion) is string;
}

// Resolves a client version against one selector table. Returns () when the table is not published,
// "" when it is published but matches nothing, else the manifest file it names.
function readSelector(string channel, string fileName, string? clientVersion) returns string?|error {
    [byte[], string]|error? stored = readSourceManifest(channel, fileName);
    if stored is error {
        return stored;
    }
    if stored is () {
        return ();
    }
    string text = check string:fromBytes(stored[0]);
    json parsed = check text.fromJsonString();
    SourceIndex selectors = check parsed.cloneWithType(SourceIndex);
    string? selected = selectManifest(selectors, clientVersion);
    if selected is () {
        return "";
    }
    if !isSourceFile(selected) {
        // These tables are hand-maintained, so a typo would otherwise become a store lookup for
        // whatever was written. Reject it as configuration, not as a missing file.
        return error(string `${fileName} names an invalid manifest file: ${selected}`);
    }
    return selected;
}

// Fails unless the document's detached signature verifies against the configured public key.
// Skipped, with a warning, when no key is configured — the state local development and tests run in.
function verifySource(string channel, string fileName, byte[] content) returns error? {
    if !sourceTrustConfigured {
        // Only reachable with allowUnsignedSource = true; startup refuses otherwise.
        return ();
    }
    byte[] pemBytes = check array:fromBase64(sourcePublicKey);
    string pem = check string:fromBytes(pemBytes);
    // The signature travels with the document it covers, so a per-line layout verifies the file it
    // actually selected rather than a fixed name that may describe a different line entirely.
    [byte[], string]|error? stored = readSourceManifest(channel, fileName + ".sig");
    if stored is error {
        return stored;
    }
    if stored is () {
        return error(string `source document ${fileName} for ${channel} has no signature`);
    }
    string signature = check string:fromBytes(stored[0]);
    boolean ok = check verifyDetachedSignature(content, signature, pem);
    if !ok {
        return error(string `source document signature verification failed for ${channel}`);
    }
    return ();
}

// Guards the CLIENT-facing read endpoints. Returns () when the request may proceed: either no
// clientTokens are configured (open, as today) or the presented bearer matches one of them.
//
// Compared over SHA-256 digests, like authGuard, so the check does not leak which prefix matched
// through timing. Digests of every candidate are computed regardless of an early match for the
// same reason.
function clientAuthGuard(http:Request request) returns http:Response? {
    if clientTokens.length() == 0 {
        return ();
    }
    string|http:HeaderNotFoundError auth = request.getHeader("Authorization");
    if auth !is string {
        return jsonResponse(401, {'error: "unauthorized"});
    }
    byte[] presented = crypto:hashSha256(auth.toBytes());
    boolean matched = false;
    foreach string token in clientTokens {
        byte[] expected = crypto:hashSha256(string `Bearer ${token}`.toBytes());
        if presented == expected {
            matched = true;
        }
    }
    if !matched {
        return jsonResponse(401, {'error: "unauthorized"});
    }
    return ();
}

function authGuard(http:Request request) returns http:Response? {
    if adminToken == "" {
        return jsonResponse(404, {'error: "not found"});
    }
    string|http:HeaderNotFoundError auth = request.getHeader("Authorization");
    if auth !is string {
        return jsonResponse(401, {'error: "unauthorized"});
    }
    byte[] presented = crypto:hashSha256(auth.toBytes());
    byte[] expected = crypto:hashSha256(string `Bearer ${adminToken}`.toBytes());
    if presented != expected {
        return jsonResponse(401, {'error: "unauthorized"});
    }
    return ();
}

// Convenience builder for JSON status responses.
function jsonResponse(int statusCode, json body) returns http:Response {
    http:Response res = new;
    res.statusCode = statusCode;
    res.setJsonPayload(body);
    return res;
}
