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

// Dynamic-server features (docs/update-mechanism-design.md §8, Phase 3): a kill-switch
// to stop a bad update reaching new clients, and lightweight in-memory metrics. Both respect
// the serve-verbatim contract — the manifest bytes are NEVER rewritten (so the detached cosign
// signature stays valid). The kill-switch simply withholds the manifest (HTTP 204 = "no update
// available", which the client already treats as up-to-date) for revoked scopes.

import ballerina/log;

// ---------------------------------------------------------------------------
// Kill-switch (revocations)
// ---------------------------------------------------------------------------

// A revoked scope. `platform`/`arch` of "*" match any, so an operator can revoke a
// single (channel, platform, arch), a whole platform, or an entire channel. The set is persisted as
// a JSON array through the shared control store — `manifests/control/revocations.json` in the
// bucket, or <dataDir>/revocations.json for a single-process local deployment — so it survives
// restarts AND is seen by every replica.
public type Revocation record {
    string channel;
    string platform = "*";
    string arch = "*";
};

// Admin request body for POST /api/v1/admin/revocations.
public type RevocationRequest record {
    string channel;
    string platform?;
    string arch?;
    boolean revoked;
};

const REVOCATIONS_FILE = "revocations.json";

// Reads the persisted revocation list (empty when absent).
//
// Goes through the shared control store rather than straight to disk: on a multi-replica deployment
// a local file would make a kill-switch apply only to the replica that served the POST setting it.
function loadRevocations() returns Revocation[]|error {
    [byte[], string]|error? stored = readControlFile(REVOCATIONS_FILE);
    if stored is error {
        return stored;
    }
    if stored is () {
        return [];
    }
    string text = check string:fromBytes(stored[0]);
    json data = check text.fromJsonString();
    return data.cloneWithType();
}

// Persists the revocation list.
function saveRevocations(Revocation[] revocations) returns error? {
    return writeControlFile(REVOCATIONS_FILE, revocations.toJsonString().toBytes());
}

// True when the given (channel, platform, arch) is currently revoked. A read failure is
// treated as "not revoked" (fail-open) so a corrupt file never blocks all updates; it is logged.
function isRevoked(string channel, string platform, string arch) returns boolean {
    Revocation[]|error revocations = loadRevocations();
    if revocations is error {
        log:printError("failed to read revocations; treating scope as not revoked", revocations);
        return false;
    }
    foreach Revocation r in revocations {
        if r.channel == channel
                && (r.platform == "*" || r.platform == platform)
                && (r.arch == "*" || r.arch == arch) {
            return true;
        }
    }
    return false;
}

// Adds (revoked=true) or removes (revoked=false) a revocation for an exact scope and returns
// the updated list. The read-modify-write is serialized with a lock so concurrent admin calls
// don't clobber each other.
function setRevocation(string channel, string platform, string arch, boolean revoked) returns Revocation[]|error {
    lock {
        Revocation[] current = check loadRevocations();
        Revocation[] next = [];
        foreach Revocation r in current {
            if !(r.channel == channel && r.platform == platform && r.arch == arch) {
                next.push(r);
            }
        }
        if revoked {
            next.push({channel, platform, arch});
        }
        check saveRevocations(next);
        return next.clone();
    }
}

// ---------------------------------------------------------------------------
// Metrics (in-memory; reset on restart)
// ---------------------------------------------------------------------------

isolated map<int> metricCounts = {};

// Records one update check: increments the per-scope counter and, when supplied, the
// per-appVersion counter. Keys: "<channel>/<platform>/<arch>" and "appVersion:<v>".
isolated function recordCheck(string channel, string platform, string arch, string? appVersion) {
    lock {
        string scopeKey = string `${channel}/${platform}/${arch}`;
        metricCounts[scopeKey] = (metricCounts[scopeKey] ?: 0) + 1;
        if appVersion is string {
            string versionKey = string `appVersion:${appVersion}`;
            metricCounts[versionKey] = (metricCounts[versionKey] ?: 0) + 1;
        }
    }
}

// Returns a snapshot copy of the current counters.
isolated function metricsSnapshot() returns map<int> {
    lock {
        return metricCounts.clone();
    }
}
