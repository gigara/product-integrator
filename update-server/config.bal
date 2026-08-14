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

// Restrict macOS core-app updates to the client's own minor line: a 5.1.x client is
// never offered a 5.2.x build. Enforced server-side from the `wiversion` the client
// sends on the Squirrel feed request. Set to false to deliberately push a whole
// channel across a minor boundary without shipping a new client.
//
// Clients that predate `wiversion` send nothing and cannot be placed on a line, so
// they keep the previous behaviour (offered whatever the channel publishes) — the
// alternative would strand them with no updates at all, permanently.
configurable boolean restrictAppUpdatesToMinorLine = true;

// Server-side overrides of the published index, applied BEFORE it.
//
// index.json is maintained automatically — every release claims its own line as it publishes — so
// there is otherwise no way to intervene between releases. Two cases need one: repointing a line at
// an earlier document after a bad release, and moving an end-of-life line onto a newer one.
//
// This is deployment configuration rather than a file in the object store on purpose. An override
// decides which build a whole population of clients is offered, so it should travel through the
// same review and deploy path as the rest of the server, and it should not be rewritable by anyone
// holding the admin publish token.
//
// A list of EXCEPTIONS, not a routing table: the first entry whose `clients` selector matches wins,
// and matching nothing falls through to the index. `clients` takes the same forms the index does —
// an exact version (5.1.4), a wildcard (5.1.x, 5.x, *), or a range (">=5.1.0 <5.2.0"). Leave
// `channel` unset to apply to every channel.
//
//   [[lineOverrides]]
//   clients = "5.1.x"
//   manifest = "source-5.3.0.json"
//   note = "5.1 end of life - migrate onto 5.3"
configurable LineOverride[] lineOverrides = [];

// Tokens accepted on the CLIENT-facing read endpoints (manifest + Squirrel feed). Empty (the
// default) leaves those endpoints open, which is the behaviour every existing client depends on.
// Populate it to require `Authorization: Bearer <token>`; unauthenticated checks then get 401.
//
// A flat token list is deliberately the first step: it gates ACCESS without yet modelling
// entitlement. Per-client composition (which components a given subject may see) needs a real
// subject -> entitlement mapping, which belongs with the product decision, not here.
configurable string[] clientTokens = [];

// Base64-encoded PEM public key (`base64 < cosign.pub`) that the CI signs the source document with.
// When set, a document whose detached signature is missing or invalid is REFUSED — the server
// composes every client's response from this file, so a compromised bucket that could swap it would
// otherwise be deciding what every client installs. Artifact statements still prevent installing
// unsigned code, but the decisions themselves would be the attacker's.
//
// Empty (the default) skips the check with a warning, which is what local development and the test
// suite run with.
configurable string sourcePublicKey = "";

// Cache-Control max-age (seconds) sent with manifest/signature responses.
// Clients additionally revalidate with the ETag, so this can be modest.
configurable int cacheMaxAge = 300;
