/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/**
 * Unit tests for buildRemoteAwareUri.
 * No VS Code dependency — runs with plain Node.js + mocha.
 */

import * as assert from "assert";
import { buildRemoteAwareUri, UriLike } from "../../utils/uriUtils";

function makeUri(scheme: string, authority: string, uriPath: string): UriLike {
    return {
        scheme,
        authority,
        path: uriPath,
        with(change: { path: string }): UriLike {
            return makeUri(this.scheme, this.authority, change.path);
        },
        toString(): string {
            return authority ? `${scheme}://${authority}${uriPath}` : `${scheme}://${uriPath}`;
        },
    };
}

const fakeFileUriFactory = (p: string): UriLike => makeUri("file", "", p);

describe("buildRemoteAwareUri", () => {
    describe("with an existing remote workspace URI", () => {
        const remoteUri = makeUri("vscode-remote", "ssh-remote+my-host", "/workspace/project");

        it("preserves the remote scheme", () => {
            const result = buildRemoteAwareUri("/new/path", remoteUri, fakeFileUriFactory);
            assert.strictEqual(result.scheme, "vscode-remote");
        });

        it("preserves the remote authority", () => {
            const result = buildRemoteAwareUri("/new/path", remoteUri, fakeFileUriFactory);
            assert.strictEqual(result.authority, "ssh-remote+my-host");
        });

        it("uses the supplied target path", () => {
            const result = buildRemoteAwareUri("/new/path", remoteUri, fakeFileUriFactory);
            assert.strictEqual(result.path, "/new/path");
        });

        it("does not fall back to the fileUriFactory", () => {
            let factoryCalled = false;
            buildRemoteAwareUri("/new/path", remoteUri, (p) => {
                factoryCalled = true;
                return fakeFileUriFactory(p);
            });
            assert.strictEqual(factoryCalled, false);
        });
    });

    describe("with a Devant cloud editor URI pattern", () => {
        const devantUri = makeUri(
            "vscode-remote",
            "c06bfa53-8eee-40c1-b975-ea8a654dc4c1.editor.e1-us-east-azure.devant.dev",
            "/tmp/chouser/project"
        );

        it("preserves the Devant remote authority", () => {
            const result = buildRemoteAwareUri("/tmp/chouser/new-project", devantUri, fakeFileUriFactory);
            assert.strictEqual(result.scheme, "vscode-remote");
            assert.strictEqual(result.authority, "c06bfa53-8eee-40c1-b975-ea8a654dc4c1.editor.e1-us-east-azure.devant.dev");
            assert.strictEqual(result.path, "/tmp/chouser/new-project");
        });
    });

    describe("without an existing workspace URI (local session)", () => {
        it("falls back to the fileUriFactory", () => {
            let factoryArg: string | undefined;
            buildRemoteAwareUri("/local/path", undefined, (p) => {
                factoryArg = p;
                return fakeFileUriFactory(p);
            });
            assert.strictEqual(factoryArg, "/local/path");
        });

        it("returns a file-scheme URI", () => {
            const result = buildRemoteAwareUri("/local/path", undefined, fakeFileUriFactory);
            assert.strictEqual(result.scheme, "file");
        });

        it("uses the supplied target path", () => {
            const result = buildRemoteAwareUri("/local/path", undefined, fakeFileUriFactory);
            assert.strictEqual(result.path, "/local/path");
        });
    });

    describe("regression: plain Uri.file() would have broken the remote case", () => {
        it("a file:// URI loses the remote authority — confirming why the fix is needed", () => {
            const brokenLocalUri = makeUri("file", "", "/new/path");
            assert.strictEqual(brokenLocalUri.scheme, "file");
            assert.strictEqual(brokenLocalUri.authority, "");
        });

        it("buildRemoteAwareUri does NOT produce a file:// URI when a remote workspace exists", () => {
            const remoteUri = makeUri("vscode-remote", "ssh-remote+host", "/original");
            const result = buildRemoteAwareUri("/new/path", remoteUri, fakeFileUriFactory);
            assert.notStrictEqual(result.scheme, "file");
        });
    });
});
