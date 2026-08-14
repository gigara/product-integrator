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

// Filesystem-backed artifact store. Resolves, reads, and writes manifest
// artifacts under the configured data directory with strict path validation.

import ballerina/crypto;
import ballerina/file;
import ballerina/io;

// Fixed allowlists for the path segments that are not operator-configured.
// Kept in sync with the platforms/arches CI publishes for.
final readonly & string[] ALLOWED_PLATFORMS = ["darwin", "linux", "win32"];
final readonly & string[] ALLOWED_ARCHS = ["x64", "arm64"];
final readonly & string[] ALLOWED_FILES = ["manifest.json", "manifest.json.sig", "manifest.json.pem"];

// Files the source layout may contain, as a pattern rather than a fixed list: each release
// publishes its own immutable document (source-5.2.1.json) alongside the index that selects it,
// so the names are not knowable in advance.
//
// Accepts `index.json`, `source.json` (the single-document layout that predates the index) and
// `source-<version>.json`, each optionally suffixed `.sig`. The version part is restricted to
// characters that appear in a version string — deliberately excluding `/`, `\` and `.` runs — so a
// name can never climb out of the channel directory or the bucket prefix it is joined to.
//
// Overrides are NOT here: they are deployment configuration (see `lineOverrides`), not a file
// anyone holding the admin publish token can write.
isolated function isSourceFile(string fileName) returns boolean {
    if fileName.includes("..") || fileName.includes("/") || fileName.includes("\\") {
        return false;
    }
    return re `^(index|source|source-[A-Za-z0-9][A-Za-z0-9._+-]{0,63})\.json(\.sig)?$`.isFullMatch(fileName);
}

final readonly & map<string> CONTENT_TYPES = {
    "manifest.json": "application/json",
    "manifest.json.sig": "application/octet-stream",
    "manifest.json.pem": "application/x-pem-file"
};

final readonly & string[] HEX = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"];

// Validates every client-supplied path segment against an allowlist. Returns an
// error (surfaced as 400) for any segment that is not explicitly permitted, so
// path/key traversal is impossible in both the local and the S3 store.
function validateSegments(string channel, string platform, string arch, string fileName) returns error? {
    if allowedChannels.indexOf(channel) !is int {
        return error(string `unsupported channel: ${channel}`);
    }
    if ALLOWED_PLATFORMS.indexOf(platform) !is int {
        return error(string `unsupported platform: ${platform}`);
    }
    if ALLOWED_ARCHS.indexOf(arch) !is int {
        return error(string `unsupported arch: ${arch}`);
    }
    if ALLOWED_FILES.indexOf(fileName) !is int {
        return error(string `unsupported file: ${fileName}`);
    }
    return ();
}

// Resolves the on-disk path for a request (local mode).
function resolvePath(string channel, string platform, string arch, string fileName) returns string|error {
    check validateSegments(channel, platform, arch, fileName);
    return file:joinPath(dataDir, "api", "v1", "updates", channel, platform, arch, fileName);
}

// Store-agnostic read: validates the segments, then reads from S3 (when s3Bucket is
// configured) or the local data directory. Returns () when the artifact is absent.
function readStoredArtifact(string channel, string platform, string arch, string fileName)
        returns [byte[], string]|error? {
    check validateSegments(channel, platform, arch, fileName);
    if s3Bucket != "" {
        return readS3Artifact(string `manifests/${channel}/${platform}/${arch}/${fileName}`);
    }
    string path = check resolvePath(channel, platform, arch, fileName);
    return readArtifact(path);
}

// Reads the single source document for a channel — the one file CI publishes and the server
// composes every response from. Clients never fetch it.
//
// Kept separate from readStoredArtifact() because its path has no platform/arch: the whole point
// of the source document is that one file covers every target.
function readSourceManifest(string channel, string fileName) returns [byte[], string]|error? {
    if allowedChannels.indexOf(channel) !is int {
        return error(string `unsupported channel: ${channel}`);
    }
    if !isSourceFile(fileName) {
        return error(string `unsupported file: ${fileName}`);
    }
    if s3Bucket != "" {
        return readS3Artifact(string `manifests/${channel}/${fileName}`);
    }
    string path = check file:joinPath(dataDir, "api", "v1", "updates", channel, fileName);
    return readArtifact(path);
}

// Admin publish of the source document.
function writeSourceManifest(string channel, string fileName, byte[] content) returns error? {
    if allowedChannels.indexOf(channel) !is int {
        return error(string `unsupported channel: ${channel}`);
    }
    if !isSourceFile(fileName) {
        return error(string `unsupported file: ${fileName}`);
    }
    if s3Bucket != "" {
        return writeS3Artifact(string `manifests/${channel}/${fileName}`, content);
    }
    string path = check file:joinPath(dataDir, "api", "v1", "updates", channel, fileName);
    return writeArtifact(path, content);
}

// Operator state that must be visible to EVERY replica, not just the one that served the write.
//
// The kill-switch lives here. A revocation persisted to a local file applies only to the replica
// that happened to receive the POST, so on a multi-replica deployment "stop shipping this update"
// silently becomes "stop shipping it to roughly one in N clients" — the failure mode that matters
// least when things are fine and most when they are not. In S3 mode this rides the same bucket the
// documents do (under the private manifests/ prefix); locally it stays a file, which is correct
// because a local deployment is one process.
function readControlFile(string fileName) returns [byte[], string]|error? {
    if !isControlFile(fileName) {
        return error(string `unsupported control file: ${fileName}`);
    }
    if s3Bucket != "" {
        return readS3Artifact(string `manifests/control/${fileName}`);
    }
    string path = check file:joinPath(dataDir, fileName);
    return readArtifact(path);
}

function writeControlFile(string fileName, byte[] content) returns error? {
    if !isControlFile(fileName) {
        return error(string `unsupported control file: ${fileName}`);
    }
    if s3Bucket != "" {
        return writeS3Artifact(string `manifests/control/${fileName}`, content);
    }
    string path = check file:joinPath(dataDir, fileName);
    return writeArtifact(path, content);
}

isolated function isControlFile(string fileName) returns boolean {
    return fileName == "revocations.json";
}

// Store-agnostic write (admin publish): S3 write-through or the local data directory.
function writeStoredArtifact(string channel, string platform, string arch, string fileName, byte[] content)
        returns error? {
    check validateSegments(channel, platform, arch, fileName);
    if s3Bucket != "" {
        return writeS3Artifact(string `manifests/${channel}/${platform}/${arch}/${fileName}`, content);
    }
    string path = check resolvePath(channel, platform, arch, fileName);
    return writeArtifact(path, content);
}

// Reads an artifact. Returns () when the file does not exist (surfaced as 404),
// an error on real I/O failures, or a [bytes, etag] tuple on success.
function readArtifact(string path) returns [byte[], string]|error? {
    boolean exists = check file:test(path, file:EXISTS);
    if !exists {
        return ();
    }
    byte[] content = check io:fileReadBytes(path);
    string etag = string `"${sha256Hex(content)}"`;
    return [content, etag];
}

// Writes an artifact (admin publish), creating parent directories as needed.
function writeArtifact(string path, byte[] content) returns error? {
    string parent = check file:parentPath(path);
    boolean parentExists = check file:test(parent, file:EXISTS);
    if !parentExists {
        check file:createDir(parent, file:RECURSIVE);
    }
    check io:fileWriteBytes(path, content);
}

// Returns the MIME type for a known artifact file name.
function contentTypeFor(string fileName) returns string {
    return CONTENT_TYPES[fileName] ?: "application/octet-stream";
}

// Lowercase hex encoding of the SHA-256 digest, used as the ETag value.
isolated function sha256Hex(byte[] data) returns string {
    byte[] digest = crypto:hashSha256(data);
    string out = "";
    foreach byte b in digest {
        int v = <int>b;
        out = out + HEX[v / 16] + HEX[v % 16];
    }
    return out;
}

// Extracts the "<major>.<minor>" line from a version string, e.g. 5.1.2-testalpha1 -> "5.1".
// Returns () when the version has no minor component or either component is non-numeric, so
// callers can skip line-based decisions rather than guess. Never used to build a filesystem
// path — `wiversion` is untrusted client input.
public isolated function minorLine(string version) returns string? {
    string[] parts = re `\.`.split(version.trim());
    if parts.length() < 2 {
        return ();
    }
    string major = parts[0];
    // The minor component may carry a pre-release suffix on a 2-part version (5.1-alpha1).
    string minor = re `[^0-9]`.split(parts[1])[0];
    if major.length() == 0 || minor.length() == 0 {
        return ();
    }
    int|error majorNum = int:fromString(major);
    int|error minorNum = int:fromString(minor);
    if majorNum is error || minorNum is error {
        return ();
    }
    return string `${majorNum}.${minorNum}`;
}
