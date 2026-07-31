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

// Configurable values for the WSO2 Integrator update server.
// Override any of these via Config.toml, environment variables, or CLI args.
// See https://ballerina.io/learn/configure-a-sample-ballerina-service/ for the
// configuration precedence rules.

// TCP port the HTTP listener binds to.
configurable int port = 9600;

// Root directory that holds the published manifest tree. The server resolves
// artifacts at <dataDir>/api/v1/updates/<channel>/<platform>/<arch>/<file>.
// Relative paths are resolved against the current working directory.
configurable string dataDir = "data";

// Channels the server will serve. Requests for any other channel are rejected
// with 400. This is the only client-supplied path segment that is not a fixed
// allowlist, so it is validated against this list to prevent path traversal.
configurable string[] allowedChannels = ["stable", "beta", "insider"];

// ---- S3-backed store (production) ----
// When s3Bucket is set, manifests and Squirrel feeds are read from
// s3://<s3Bucket>/manifests/<channel>/<platform>/<arch>/<file> — the layout the CI
// publish-update-manifest job writes — instead of the local data directory. Reads go
// through a short in-memory cache so client polls don't hit S3 on every request.
// When empty (the default) the server serves from the local dataDir as before.
configurable string s3Bucket = "";
configurable string s3Region = "us-east-1";
configurable string s3AccessKeyId = "";
configurable string s3SecretAccessKey = "";

// Seconds an S3 read (hit or miss) is served from the in-memory cache before
// re-fetching. Bounds how long a newly published manifest takes to go live.
configurable decimal s3CacheSeconds = 60;

// Bearer token required for the admin publish (PUT) endpoint. When empty
// (the default) the publish endpoint is disabled entirely and responds 404.
configurable string adminToken = "";

// Cache-Control max-age (seconds) sent with manifest/signature responses.
// Clients additionally revalidate with the ETag, so this can be modest.
configurable int cacheMaxAge = 300;
