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

// No vscode import — this file must stay free of VS Code dependencies so it can be unit-tested
// with plain Node.js without launching the extension host.

export interface UriLike {
    readonly scheme: string;
    readonly authority: string;
    readonly path: string;
    with(change: { path: string }): UriLike;
    toString(): string;
}

/**
 * Builds a folder URI for `vscode.openFolder`, preserving the remote scheme and authority
 * of the existing workspace URI.
 *
 * In VS Code Remote / cloud editor, every workspace folder URI carries a remote authority
 * (e.g. `vscode-remote://ssh-remote+host/project`). Constructing a plain `Uri.file(path)`
 * drops the authority, causing VS Code to open the folder on the local client instead of
 * the remote server — resulting in a wrong workspace root, broken webviews, and the lang
 * server receiving unrelated files.
 *
 * @param targetPath     Absolute path on the remote (or local) filesystem.
 * @param existingUri    Current workspace folder URI whose scheme/authority should be kept.
 * @param fileUriFactory Factory for local file URIs; pass `Uri.file` from the vscode module.
 */
export function buildRemoteAwareUri(
    targetPath: string,
    existingUri: Pick<UriLike, "with"> | undefined,
    fileUriFactory: (p: string) => UriLike
): UriLike {
    return existingUri ? existingUri.with({ path: targetPath }) : fileUriFactory(targetPath);
}
