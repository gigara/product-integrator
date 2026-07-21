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

final readonly & map<string> CONTENT_TYPES = {
    "manifest.json": "application/json",
    "manifest.json.sig": "application/octet-stream",
    "manifest.json.pem": "application/x-pem-file"
};

final readonly & string[] HEX = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"];

// Resolves the on-disk path for a request, validating every client-supplied
// segment against an allowlist. Returns an error (surfaced as 400) for any
// segment that is not explicitly permitted, so path traversal is impossible.
function resolvePath(string channel, string platform, string arch, string fileName) returns string|error {
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
    return file:joinPath(dataDir, "api", "v1", "updates", channel, platform, arch, fileName);
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
function sha256Hex(byte[] data) returns string {
    byte[] digest = crypto:hashSha256(data);
    string out = "";
    foreach byte b in digest {
        int v = <int>b;
        out = out + HEX[v / 16] + HEX[v % 16];
    }
    return out;
}
