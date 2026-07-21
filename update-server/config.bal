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

// Bearer token required for the admin publish (PUT) endpoint. When empty
// (the default) the publish endpoint is disabled entirely and responds 404.
configurable string adminToken = "";

// Cache-Control max-age (seconds) sent with manifest/signature responses.
// Clients additionally revalidate with the ETag, so this can be modest.
configurable int cacheMaxAge = 300;
