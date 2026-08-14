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


// ---------------------------------------------------------------------------
// Kill-switch (revocations)
// ---------------------------------------------------------------------------

// A revoked scope. `platform`/`arch` of "*" match any, so an operator can revoke a single
// (channel, platform, arch), a whole platform, or an entire channel.
//
// Supplied as deployment configuration (see `revocations` in config.bal), like the line overrides.
// It was previously a mutable file written by an admin endpoint; that made the most destructive
// control in the system — withhold updates from everyone — settable by anyone holding the CI
// publish token, and left no record of who withheld what or when.
public type Revocation record {
    string channel;
    string platform = "*";
    string arch = "*";
    // Why this scope was withheld. Never read by the server; it exists so the config records the
    // reason next to the decision, which is most of the value of moving this out of an endpoint.
    string note?;
};

// True when the given (channel, platform, arch) is currently revoked.
isolated function isRevoked(string channel, string platform, string arch) returns boolean {
    return matchesRevocation(revocations, channel, platform, arch);
}

// The matching rule itself, taking the list as an argument so it can be tested without depending on
// what a particular deployment configures — the same split as pickOverride().
isolated function matchesRevocation(Revocation[] configured, string channel, string platform, string arch)
        returns boolean {
    foreach Revocation r in configured {
        if r.channel == channel
                && (r.platform == "*" || r.platform == platform)
                && (r.arch == "*" || r.arch == arch) {
            return true;
        }
    }
    return false;
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
