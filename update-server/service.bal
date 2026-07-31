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
import ballerina/log;

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
        if s3Bucket != "" {
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

    // Serves a manifest or its companion signature/certificate.
    // `appVersion` is accepted for telemetry/logging; the full manifest is
    // always returned (200) so this stays compatible with static hosting.
    resource function get api/v1/updates/[string channel]/[string platform]/[string arch]/[string fileName](
            http:Request request, string? appVersion) returns http:Response {
        string? ifNoneMatch = ();
        string|http:HeaderNotFoundError header = request.getHeader("If-None-Match");
        if header is string {
            ifNoneMatch = header;
        }
        if appVersion is string {
            log:printInfo(string `update check channel=${channel} platform=${platform} arch=${arch} appVersion=${appVersion}`);
        }
        // Dynamic features (Phase 3) apply to the manifest itself, not the signature/cert.
        if fileName == "manifest.json" {
            recordCheck(channel, platform, arch, appVersion);
            // Kill-switch: withhold the manifest for a revoked scope so NEW clients receive
            // no update (204). The manifest bytes are never rewritten — the signature is intact
            // for every client that does receive it.
            if isRevoked(channel, platform, arch) {
                log:printInfo(string `manifest withheld (revoked) channel=${channel} platform=${platform} arch=${arch}`);
                http:Response revoked = new;
                revoked.statusCode = 204;
                revoked.setHeader("Cache-Control", "no-store");
                return revoked;
            }
        }
        return buildFileResponse(channel, platform, arch, fileName, ifNoneMatch);
    }

    // Squirrel.Mac core-app update feed (macOS). Electron's autoUpdater polls
    //   GET /api/update/{darwin|darwin-arm64}/{quality}/{commit}
    // and expects 200 {url, ...} when a newer build exists, or 204 when current.
    // Derived from the channel's (cosign-signed) manifest itself: the darwin manifest
    // carries `app.commit` (the product-integrator root sha the build was produced
    // from) and `app.squirrel.url` (the editor-only .app zip on the CDN) — no separate
    // feed artifact. Every failure path deliberately degrades to 204 ("no update") —
    // a broken/missing manifest must never surface an error on each mac client's check.
    resource function get api/update/[string assetId]/[string quality]/[string clientCommit]() returns http:Response {
        string? arch = assetId == "darwin" ? "x64" : assetId == "darwin-arm64" ? "arm64" : ();
        if arch is () {
            return jsonResponse(404, {'error: "unsupported asset"});
        }
        http:Response noUpdate = new;
        noUpdate.statusCode = 204;
        noUpdate.setHeader("Cache-Control", "no-store");
        recordCheck(quality, assetId, arch, ());
        // Kill-switch applies to the mac core app exactly like the component manifest.
        if isRevoked(quality, "darwin", arch) {
            log:printInfo(string `squirrel feed withheld (revoked) quality=${quality} arch=${arch}`);
            return noUpdate;
        }
        do {
            [byte[], string]? artifact = check readStoredArtifact(quality, "darwin", arch, "manifest.json");
            if artifact is () {
                return noUpdate; // nothing published for this channel/arch
            }
            string text = check string:fromBytes(artifact[0]);
            json parsed = check text.fromJsonString();
            Manifest manifest = check parsed.cloneWithType(Manifest);
            AppUpdate? app = manifest.app;
            if app is () {
                return noUpdate;
            }
            string? feedCommit = app?.'commit;
            SquirrelPayload? squirrel = app?.squirrel;
            if feedCommit is () || squirrel is () {
                return noUpdate; // manifest predates the embedded Squirrel feed
            }
            if feedCommit == clientCommit {
                return noUpdate; // client already runs the latest published build
            }
            log:printInfo(string `squirrel update offered quality=${quality} arch=${arch} version=${app.'version} to commit=${clientCommit}`);
            return jsonResponse(200, {
                url: squirrel.url,
                name: app.'version,
                productVersion: app.'version,
                pub_date: manifest.publishedAt
            });
        } on fail error e {
            log:printError("squirrel feed lookup failed", e);
            return noUpdate;
        }
    }

    // Admin: list current kill-switch revocations. Bearer adminToken; 404 when disabled.
    resource function get api/v1/admin/revocations(http:Request request) returns http:Response {
        http:Response? denied = authGuard(request);
        if denied is http:Response {
            return denied;
        }
        Revocation[]|error revocations = loadRevocations();
        if revocations is error {
            log:printError("failed to list revocations", revocations);
            return jsonResponse(500, {'error: "internal error"});
        }
        return jsonResponse(200, {revocations: revocations.toJson()});
    }

    // Admin: set or clear a kill-switch revocation. Body: {channel, platform?, arch?, revoked}.
    // Omitted platform/arch mean "*" (revoke the whole platform/channel).
    resource function post api/v1/admin/revocations(http:Request request, @http:Payload RevocationRequest body)
            returns http:Response {
        http:Response? denied = authGuard(request);
        if denied is http:Response {
            return denied;
        }
        Revocation[]|error updated = setRevocation(body.channel, body.platform ?: "*", body.arch ?: "*", body.revoked);
        if updated is error {
            log:printError("failed to update revocation", updated);
            return jsonResponse(400, {'error: updated.message()});
        }
        return jsonResponse(200, {revocations: updated.toJson()});
    }

    // Admin: in-memory update-check counters (per scope and per appVersion). Bearer adminToken.
    resource function get api/v1/admin/metrics(http:Request request) returns http:Response {
        http:Response? denied = authGuard(request);
        if denied is http:Response {
            return denied;
        }
        return jsonResponse(200, {checks: metricsSnapshot().toJson()});
    }

    // Admin publish: writes a manifest/signature/certificate to the store.
    // Disabled (404) unless `adminToken` is configured; requires a matching
    // `Authorization: Bearer <token>` header. Manifests are shape-validated.
    resource function put api/v1/updates/[string channel]/[string platform]/[string arch]/[string fileName](
            http:Request request) returns http:Response {
        http:Response? denied = authGuard(request);
        if denied is http:Response {
            return denied;
        }
        do {
            byte[] body = check request.getBinaryPayload();
            if fileName == "manifest.json" {
                string text = check string:fromBytes(body);
                json parsed = check text.fromJsonString();
                // Validate the manifest shape before persisting it.
                Manifest _ = check parsed.cloneWithType(Manifest);
            }
            check writeStoredArtifact(channel, platform, arch, fileName, body);
            return jsonResponse(201, {
                status: "published",
                path: string `${channel}/${platform}/${arch}/${fileName}`
            });
        } on fail error e {
            log:printError("publish failed", e);
            return jsonResponse(400, {'error: e.message()});
        }
    }
}

// Builds the response for a manifest/signature/certificate request, including
// ETag-based conditional GET (304) handling.
function buildFileResponse(string channel, string platform, string arch, string fileName, string? ifNoneMatch)
        returns http:Response {
    // Validate up front so a bad segment is a 400, distinct from store failures (500).
    error? invalid = validateSegments(channel, platform, arch, fileName);
    if invalid is error {
        return jsonResponse(400, {'error: invalid.message()});
    }

    [byte[], string]|error? artifact = readStoredArtifact(channel, platform, arch, fileName);
    if artifact is error {
        log:printError("failed to read artifact", artifact);
        return jsonResponse(500, {'error: "internal error"});
    }
    if artifact is () {
        return jsonResponse(404, {'error: "manifest not found"});
    }

    byte[] content = artifact[0];
    string etag = artifact[1];

    http:Response res = new;
    res.setHeader("ETag", etag);
    res.setHeader("Cache-Control", string `public, max-age=${cacheMaxAge}`);

    if ifNoneMatch is string && ifNoneMatch == etag {
        res.statusCode = 304;
        return res;
    }

    res.statusCode = 200;
    res.setBinaryPayload(content, contentTypeFor(fileName));
    return res;
}

// Admin authorization guard. Returns a denial response (404 when the admin API is disabled,
// 401 on a bad/absent token) or () when the caller is authorized. Tokens are compared via
// their SHA-256 digests so the comparison leaks no prefix-timing information.
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
