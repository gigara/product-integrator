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

// Turns ONE source document plus a client's self-report into that client's update set.
//
// The client still re-checks everything that matters — each artifact's signed statement, its own
// forward-only version rule, and `requires` from the signed statement — so a wrong decision here
// withholds or mis-offers an update, it can never make a client install something unsigned.

// Numeric, part-wise version comparison. Mirrors the client's compareVersions so both sides agree
// on what "newer" means, including 4-part versions (5.0.0.2).
isolated function compareVersions(string a, string b) returns int {
    string[] pa = re `\.`.split(a);
    string[] pb = re `\.`.split(b);
    int len = pa.length() > pb.length() ? pa.length() : pb.length();
    foreach int i in 0 ..< len {
        int na = i < pa.length() ? leadingInt(pa[i]) : 0;
        int nb = i < pb.length() ? leadingInt(pb[i]) : 0;
        if na > nb {
            return 1;
        }
        if na < nb {
            return -1;
        }
    }
    return 0;
}

// Leading digits of a version part; "2-testalpha1" -> 2, "abc" -> 0. Matches the client's parseInt
// behaviour, deliberately including its blind spot: a pre-release suffix does not order below its
// release. Both sides must agree, so this is fixed in both or neither.
isolated function leadingInt(string part) returns int {
    string digits = "";
    foreach string:Char ch in part {
        if ch >= "0" && ch <= "9" {
            digits = digits + ch;
        } else {
            break;
        }
    }
    if digits.length() == 0 {
        return 0;
    }
    int|error parsed = int:fromString(digits);
    return parsed is int ? parsed : 0;
}

// Whitespace-separated comparators, all of which must hold: ">=5.1.0 <5.2.0". Mirrors the client's
// satisfiesRange, including its lenient treatment of a comparator it cannot parse.
isolated function satisfiesRange(string ver, string range) returns boolean {
    string trimmed = range.trim();
    if trimmed.length() == 0 {
        return true;
    }
    foreach string comparator in re `\s+`.split(trimmed) {
        if comparator.length() == 0 {
            continue;
        }
        string op = "=";
        string value = comparator;
        foreach string candidate in [">=", "<=", ">", "<", "==", "="] {
            if comparator.startsWith(candidate) {
                op = candidate == "==" ? "=" : candidate;
                value = comparator.substring(candidate.length());
                break;
            }
        }
        value = value.trim();
        if value.length() == 0 {
            continue;
        }
        int cmp = compareVersions(ver, value);
        boolean ok = op == ">=" ? cmp >= 0
            : op == ">" ? cmp > 0
            : op == "<=" ? cmp <= 0
            : op == "<" ? cmp < 0
            : cmp == 0;
        if !ok {
            return false;
        }
    }
    return true;
}

// A rollout gate the client cannot be trusted to apply to itself: it reports its own 0-99 bucket,
// computed locally from a device id it never sends. A client that reports no bucket is held back
// from a partial rollout rather than waved through, so an old or hand-made request cannot opt
// itself into a canary.
isolated function passesRollout(Rollout? rollout, int? bucket) returns boolean {
    if rollout is () || rollout.percentage >= 100 {
        return true;
    }
    if bucket is () {
        return false;
    }
    return bucket < rollout.percentage;
}

// Picks the newest app entry this client is eligible for, or () when it is already current.
isolated function decideApp(SourceManifest src, UpdateCheckRequest req, string target) returns AppOffer? {
    SourceApp? best = ();
    foreach SourceApp app in src.apps {
        AppTarget? forTarget = app.targets[target];
        if forTarget is () {
            continue; // this release publishes nothing for the client's platform
        }
        string? appliesTo = app?.appliesTo;
        if appliesTo is string && !satisfiesRange(req.appVersion, appliesTo) {
            continue; // a different release line's entry
        }
        if compareVersions(app.'version, req.appVersion) <= 0 {
            continue; // client is already on this or newer
        }
        if !passesRollout(app?.rollout, req?.bucket) {
            continue;
        }
        if best is () || compareVersions(app.'version, best.'version) > 0 {
            best = app;
        }
    }
    if best is () {
        return ();
    }
    AppTarget chosen = <AppTarget>best.targets[target];
    AppOffer offer = {'version: best.'version, installer: chosen.installer};
    string? appCommit = best?.'commit;
    if appCommit is string {
        offer.'commit = appCommit;
    }
    SquirrelPayload? squirrel = chosen?.squirrel;
    if squirrel is SquirrelPayload {
        offer.squirrel = squirrel;
    }
    string? notes = best?.releaseNotesUrl;
    if notes is string {
        offer.releaseNotesUrl = notes;
    }
    return offer;
}

// Every component's version in this document, used to evaluate one component's `requires` against
// the state the client would reach by taking this whole set — the same "projected" view the client
// computes for itself.
isolated function projectedVersions(SourceManifest src, string target) returns map<string> {
    map<string> projected = {};
    foreach SourceComponent component in src.components {
        if component.targets.hasKey(target) {
            projected[component.id] = component.'version;
        }
    }
    return projected;
}

isolated function requiresSatisfied(SourceComponent component, UpdateCheckRequest req, map<string> projected)
        returns boolean {
    map<string>? requires = component?.requires;
    if requires is () {
        return true;
    }
    map<string> installed = req?.components ?: {};
    foreach [string, string] [depId, range] in requires.entries() {
        string? depVersion = ();
        if depId == "app" {
            // The app is compared as it is RIGHT NOW, never as it would be after a queued update:
            // the user may never restart, and a component that needs the newer app must not land
            // on the older one in the meantime.
            depVersion = req.appVersion;
        } else {
            depVersion = projected.hasKey(depId) ? projected[depId] : installed[depId];
        }
        if depVersion is () {
            return false;
        }
        if !satisfiesRange(depVersion, range) {
            return false;
        }
    }
    return true;
}

// The whole decision. Returns () when this client has nothing to take, which the caller turns
// into 204.
isolated function decideUpdates(SourceManifest src, UpdateCheckRequest req) returns UpdateCheckResponse? {
    string target = string `${req.platform}-${req.arch}`;
    map<string> installed = req?.components ?: {};
    map<string> projected = projectedVersions(src, target);

    ComponentOffer[] offers = [];
    foreach SourceComponent component in src.components {
        TargetArtifact? artifact = component.targets[target];
        if artifact is () {
            continue; // not published for this platform
        }
        string? have = installed[component.id];
        // A component the client did not mention is one it does not have — offer it. Anything it
        // reported at this version or newer is skipped; the client enforces the same rule again.
        if have is string && compareVersions(component.'version, have) <= 0 {
            continue;
        }
        if !passesRollout(component?.rollout, req?.bucket) {
            continue;
        }
        if !requiresSatisfied(component, req, projected) {
            continue;
        }
        ComponentOffer offer = {
            id: component.id,
            kind: component.kind,
            'version: component.'version,
            artifact: artifact
        };
        map<string>? requires = component?.requires;
        if requires is map<string> {
            offer.requires = requires;
        }
        string? notes = component?.releaseNotesUrl;
        if notes is string {
            offer.releaseNotesUrl = notes;
        }
        offers.push(offer);
    }

    AppOffer? app = decideApp(src, req, target);
    if app is () && offers.length() == 0 {
        return ();
    }
    UpdateCheckResponse response = {
        components: offers,
        checkedAt: src.publishedAt,
        sequence: src.sequence
    };
    if app is AppOffer {
        response.app = app;
    }
    return response;
}

// Squirrel.Mac asks by COMMIT, not version: it has no notion of our version numbers, so its feed
// answers "is the build you are running still current?" rather than "is there a newer version?".
// That is why this cannot reuse decideApp(), whose whole basis is a version comparison — a client
// that predates `wiversion` sends no version at all.
//
// Picks the newest app entry that publishes a Squirrel payload for this target and, where the
// client did report its version, belongs to that client's release line.
isolated function decideSquirrel(SourceManifest src, string target, string? wiversion) returns SourceApp? {
    SourceApp? best = ();
    foreach SourceApp app in src.apps {
        AppTarget? forTarget = app.targets[target];
        if forTarget is () {
            continue;
        }
        if forTarget?.squirrel is () {
            continue; // this target ships no Squirrel payload (windows/linux)
        }
        string? appliesTo = app?.appliesTo;
        if appliesTo is string && wiversion is string && !satisfiesRange(wiversion, appliesTo) {
            continue; // a different release line's entry
        }
        if best is () || compareVersions(app.'version, best.'version) > 0 {
            best = app;
        }
    }
    return best;
}
