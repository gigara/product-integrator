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

import ballerina/file;
import ballerina/http;
import ballerina/log;

listener http:Listener updateListener = new (port);

service / on updateListener {

    // Liveness/readiness probe.
    resource function get healthz() returns json {
        return {status: "ok", 'service: "wso2-integrator-update-server"};
    }

    // Lists the channels that currently have published content.
    resource function get api/v1/channels() returns http:Response {
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
            string path = check resolvePath(channel, platform, arch, fileName);
            byte[] body = check request.getBinaryPayload();
            if fileName == "manifest.json" {
                string text = check string:fromBytes(body);
                json parsed = check text.fromJsonString();
                // Validate the manifest shape before persisting it.
                Manifest _ = check parsed.cloneWithType(Manifest);
            }
            check writeArtifact(path, body);
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
    string|error path = resolvePath(channel, platform, arch, fileName);
    if path is error {
        return jsonResponse(400, {'error: path.message()});
    }

    [byte[], string]|error? artifact = readArtifact(path);
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
// 401 on a bad/absent token) or () when the caller is authorized.
function authGuard(http:Request request) returns http:Response? {
    if adminToken == "" {
        return jsonResponse(404, {'error: "not found"});
    }
    string|http:HeaderNotFoundError auth = request.getHeader("Authorization");
    if auth !is string || auth != string `Bearer ${adminToken}` {
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
