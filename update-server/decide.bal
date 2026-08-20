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
// on what "newer" means, including 4-part versions (5.0.0.2) and pre-releases.
//
// A pre-release ranks BELOW the release it precedes (semver §11.3): 5.1.3-testalpha1 < 5.1.3.
// Treating them as equal strands anyone on a pre-release, because the release that supersedes it
// never compares as newer and so is never offered. This MUST stay identical to the client's
// implementation in wso2ComponentsManifest.ts — if the two disagree, the server offers updates the
// client then refuses, and the user sees a check that finds something and does nothing.
isolated function compareVersions(string a, string b) returns int {
    [string, string] [coreA, preA] = splitVersion(a);
    [string, string] [coreB, preB] = splitVersion(b);
    string[] pa = re `\.`.split(coreA);
    string[] pb = re `\.`.split(coreB);
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
    if preA == "" && preB == "" {
        return 0;
    }
    // Same release core, so whichever carries no pre-release is the finished one and ranks above.
    if preA == "" {
        return 1;
    }
    if preB == "" {
        return -1;
    }
    return comparePreRelease(preA, preB);
}

// Splits "5.1.3-alpha.2+build" into its release core and pre-release; build metadata is dropped.
isolated function splitVersion(string version) returns [string, string] {
    string trimmed = version.trim();
    int? plus = trimmed.indexOf("+");
    string withoutBuild = plus is int ? trimmed.substring(0, plus) : trimmed;
    int? dash = withoutBuild.indexOf("-");
    if dash is int {
        return [withoutBuild.substring(0, dash), withoutBuild.substring(dash + 1)];
    }
    return [withoutBuild, ""];
}

// Dot-separated pre-release identifiers: numeric compare numerically and rank below alphanumeric.
isolated function comparePreRelease(string a, string b) returns int {
    string[] ia = re `\.`.split(a);
    string[] ib = re `\.`.split(b);
    int len = ia.length() > ib.length() ? ia.length() : ib.length();
    foreach int i in 0 ..< len {
        if i >= ia.length() {
            return -1; // a smaller set of identifiers ranks lower: alpha < alpha.1
        }
        if i >= ib.length() {
            return 1;
        }
        int? nx = allDigits(ia[i]) ? intOrZero(ia[i]) : ();
        int? ny = allDigits(ib[i]) ? intOrZero(ib[i]) : ();
        if nx is int && ny is int {
            if nx != ny {
                return nx < ny ? -1 : 1;
            }
            continue;
        }
        if nx is int {
            return -1;
        }
        if ny is int {
            return 1;
        }
        if ia[i] != ib[i] {
            return ia[i] < ib[i] ? -1 : 1;
        }
    }
    return 0;
}

isolated function allDigits(string s) returns boolean {
    if s.length() == 0 {
        return false;
    }
    foreach string:Char ch in s {
        if ch < "0" || ch > "9" {
            return false;
        }
    }
    return true;
}

isolated function intOrZero(string s) returns int {
    int|error parsed = int:fromString(s);
    return parsed is int ? parsed : 0;
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

// Does a client version match an index selector?
//
// Three forms, checked in this order:
//   *              — everything (the catch-all an index usually ends with)
//   5.1.x / 5.x    — wildcard: the segments before the wildcard must match exactly
//   >=5.1.0 <5.2.0 — a range, using the same comparators as `requires`
//   5.1.4          — anything else is an exact version
//
// The wildcard form is checked before the range form because it is not a range: "5.1.x" has no
// comparator, so satisfiesRange would read it as an equality test against the literal "5.1.x".
public isolated function matchesSelector(string clientVersion, string selector) returns boolean {
    string trimmed = selector.trim();
    if trimmed.length() == 0 || trimmed == "*" {
        return true;
    }
    if trimmed.includes("x") || trimmed.includes("X") || trimmed.includes("*") {
        return matchesWildcard(clientVersion, trimmed);
    }
    if trimmed.startsWith(">") || trimmed.startsWith("<") || trimmed.startsWith("=") {
        return satisfiesRange(clientVersion, trimmed);
    }
    return compareVersions(clientVersion, trimmed) == 0;
}

// "5.1.x" matches 5.1.0, 5.1.4, 5.1.4-beta; "5.x" matches any 5.*. Everything from the wildcard
// segment on is unconstrained, so trailing segments in the client's version cannot make it miss.
isolated function matchesWildcard(string clientVersion, string selector) returns boolean {
    // Compare against the release core only: a pre-release or build suffix (5.1.4-beta) belongs to
    // the same line as 5.1.4, and splitting it off keeps the segment comparison numeric.
    string core = releaseCore(clientVersion);
    string[] want = re `\.`.split(selector);
    string[] have = re `\.`.split(core);
    foreach int i in 0 ..< want.length() {
        string segment = want[i].trim();
        if segment == "x" || segment == "X" || segment == "*" {
            return true; // this segment and everything after it is unconstrained
        }
        if i >= have.length() || have[i] != segment {
            return false;
        }
    }
    // No wildcard segment was reached, so the selector was an exact version after all.
    return want.length() == have.length();
}

// The numeric core of a version: "5.1.4-beta.2+build" -> "5.1.4".
isolated function releaseCore(string ver) returns string {
    string core = ver.trim();
    int? dash = core.indexOf("-");
    if dash is int {
        core = core.substring(0, dash);
    }
    int? plus = core.indexOf("+");
    if plus is int {
        core = core.substring(0, plus);
    }
    return core;
}

// The server-configured override for this client, or () when none applies.
//
// First match wins, like the index, so an operator can put a narrow exception above a broader one.
// An entry without `channel` applies to every channel; an entry with one applies only to that
// channel, which is what lets a line be moved on beta without touching stable.
isolated function lineOverrideFor(string channel, string? clientVersion) returns string? {
    return pickOverride(lineOverrides, channel, clientVersion);
}

// The selection rule itself, taking the list as an argument so it can be tested without depending
// on what a particular deployment happens to configure.
isolated function pickOverride(LineOverride[] configured, string channel, string? clientVersion)
        returns string? {
    foreach LineOverride entry in configured {
        string? scope = entry?.channel;
        if scope is string && scope != channel {
            continue;
        }
        if clientVersion is () {
            // A client that reports no version cannot be placed on a line, so only an
            // unconstrained override can claim it — anything else would be a guess.
            if entry.clients.trim() == "*" {
                return entry.manifest;
            }
            continue;
        }
        if matchesSelector(clientVersion, entry.clients) {
            return entry.manifest;
        }
    }
    return ();
}

// The document that serves this client's line, or () when the index covers no line it belongs to.
// First match wins; see IndexEntry for why the order is the contract.
public isolated function selectManifest(SourceIndex index, string? clientVersion) returns string? {
    foreach IndexEntry entry in index.entries {
        if clientVersion is () {
            // A client that reports no version (an old Squirrel feed request) can only be served by
            // an entry that constrains nothing; anything else would be a guess about its line.
            if entry.'match.trim() == "*" {
                return entry.manifest;
            }
            continue;
        }
        if matchesSelector(clientVersion, entry.'match) {
            return entry.manifest;
        }
    }
    return ();
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
isolated function decideApp(SourceManifest src, UpdateCheckRequest req, string target,
        boolean viaOverride = false) returns AppOffer? {
    SourceApp? best = ();
    foreach SourceApp app in src.apps {
        AppTarget? forTarget = app.targets[target];
        if forTarget is () {
            continue; // this release publishes nothing for the client's platform
        }
        string? appliesTo = app?.appliesTo;
        // An operator override skips this: pointing a line at a document is an instruction to serve
        // it, and the document's own range describes the line it was BUILT for, which by definition
        // is not the line being migrated. Honouring it here would make an override move a client's
        // components while silently leaving its app behind.
        if !viaOverride && appliesTo is string && !satisfiesRange(req.appVersion, appliesTo) {
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

// Whether an entry belongs to THIS client's release line.
//
// A document may carry several entries for one component id — that is how one file serves 5.1.x and
// 5.2.x at once — and `requires.app` is what tells them apart. It is evaluated on its own here,
// before any projection, because it depends only on the version the client is running and so cannot
// be circular, whereas component-to-component requires can be.
isolated function onClientsLine(SourceComponent component, UpdateCheckRequest req) returns boolean {
    map<string>? requires = component?.requires;
    if requires is () {
        return true;
    }
    string? appRange = requires["app"];
    if appRange is () {
        return true;
    }
    return satisfiesRange(req.appVersion, appRange);
}

// The single entry per component id that applies to this client: on its line, published for its
// target, and the newest where ranges overlap.
//
// Collapsing to one entry per id BEFORE deciding is what stops a document with per-line entries
// offering the same component twice, and stops the projection below resolving a dependency against
// another line's version — which would silently evaluate `requires` against a version this client
// can never be given.
isolated function applicableComponents(SourceManifest src, UpdateCheckRequest req, string target)
        returns map<SourceComponent> {
    map<SourceComponent> best = {};
    foreach SourceComponent component in src.components {
        if !component.targets.hasKey(target) {
            continue;
        }
        if !onClientsLine(component, req) {
            continue;
        }
        SourceComponent? chosen = best[component.id];
        if chosen is () || compareVersions(component.'version, chosen.'version) > 0 {
            best[component.id] = component;
        }
    }
    return best;
}

// The versions this client would be on after taking everything applicable to it — the same
// "projected" view the client computes for itself.
isolated function projectedVersions(map<SourceComponent> applicable) returns map<string> {
    map<string> projected = {};
    foreach SourceComponent component in applicable {
        projected[component.id] = component.'version;
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
isolated function decideUpdates(SourceManifest src, UpdateCheckRequest req,
        boolean viaOverride = false) returns UpdateCheckResponse? {
    string target = string `${req.platform}-${req.arch}`;
    map<string> installed = req?.components ?: {};
    map<SourceComponent> applicable = applicableComponents(src, req, target);
    map<string> projected = projectedVersions(applicable);

    ComponentOffer[] offers = [];
    foreach SourceComponent component in applicable {
        TargetArtifact artifact = <TargetArtifact>component.targets[target];
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

    AppOffer? app = decideApp(src, req, target, viaOverride);
    if app is () && offers.length() == 0 {
        return ();
    }
    UpdateCheckResponse response = {
        components: offers,
        publishedAt: src.publishedAt,
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
isolated function decideSquirrel(SourceManifest src, string target, string? wiversion,
        boolean viaOverride = false) returns SourceApp? {
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
        if !viaOverride && appliesTo is string && wiversion is string && !satisfiesRange(wiversion, appliesTo) {
            continue; // a different release line's entry
        }
        if best is () || compareVersions(app.'version, best.'version) > 0 {
            best = app;
        }
    }
    return best;
}
