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

// Storage for the update source documents: the per-release documents CI publishes and the index
// that selects between them. Reads and writes go to S3 when a bucket is configured, otherwise to
// the local data directory. File names are validated before they are joined to any path.

import ballerina/crypto;
import ballerina/file;
import ballerina/io;

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


final readonly & string[] HEX = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"];

// Reads one source-layout file for a channel — a release's document, its signature, or the index.
// The server composes every response from these; clients never fetch them.
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
    if manifestsBaseUrl != "" {
        return readHttpsArtifact(string `${channel}/${fileName}`);
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
    if manifestsBaseUrl != "" {
        // Refuse rather than fall through to the local directory: in this mode reads come from the
        // public base URL, so a local write would appear to succeed and then never be served.
        return error("cannot publish while reading manifests over HTTPS; publish to the bucket instead");
    }
    string path = check file:joinPath(dataDir, "api", "v1", "updates", channel, fileName);
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
