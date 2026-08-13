#!/usr/bin/env node
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

// Renders a WSO2 Integrator update manifest (see docs/update-mechanism-design.md §4.2) for a
// given (channel, platform, arch) from ci/build/update-manifest.config.json and
// ci/build/component-versions.properties, computing each artifact's sha256 + size by
// downloading it. The output is uploaded (and cosign-signed) by the publish-update-manifest CI job.
//
// With --artifacts-base + --mirror-dir, every artifact (components + app installer) is also
// MIRRORED: the downloaded bytes are written under --mirror-dir (components/{id}/{version}/
// and app/{version}/) for the CI job to upload to the update bucket, and the manifest's URLs
// point at {artifacts-base}/<that path> (the CDN in front of the bucket) instead of the source.
// Components may declare `sourceFile` (a repo-relative file, e.g. the locally built WI extension
// VSIX) instead of `url`; those require mirroring since they have no public source URL.
//
// Usage:
//   node ci/build/generate-update-manifest.mjs \
//     --channel stable --platform darwin --arch arm64 --sequence 42 \
//     --app-version 5.0.1.0 [--app-installer-url URL] [--out manifest.json] \
//     [--artifacts-base https://cdn/artifacts --mirror-dir artifacts-mirror] [--no-download]
//
// --no-download emits placeholder hashes (structure-only; for local validation, not for release).

import { createHash } from 'node:crypto';
import { copyFileSync, createReadStream, createWriteStream, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { Readable } from 'node:stream';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(SCRIPT_DIR, '..', '..');

function parseArgs(argv) {
	const args = {};
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (a.startsWith('--')) {
			const key = a.slice(2);
			const next = argv[i + 1];
			if (next === undefined || next.startsWith('--')) {
				args[key] = true;
			} else {
				args[key] = next;
				i++;
			}
		}
	}
	return args;
}

function readVersions(file) {
	const versions = {};
	for (const line of readFileSync(file, 'utf8').split('\n')) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith('#')) {
			continue;
		}
		const eq = trimmed.indexOf('=');
		if (eq === -1) {
			continue;
		}
		versions[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
	}
	return versions;
}

function substitute(template, vars) {
	return template.replace(/\{(\w+)\}/g, (_m, key) => (vars[key] !== undefined ? String(vars[key]) : `{${key}}`));
}

// Guards every value interpolated into a mirror path / CDN URL segment. Rejects path
// separators, traversal, and URL-hostile characters so a malformed source URL or version
// can never write outside the mirror dir or produce a broken artifact URL.
function safeSegment(value, what) {
	if (!/^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(value) || value.includes('..')) {
		throw new Error(`Unsafe ${what} for artifact path: '${value}'`);
	}
	return value;
}

// Streams the artifact once: hashes it, and (when mirrorPath is set) writes the same bytes to
// disk for the CI job to upload to the update bucket.
// Fetch an artifact, coping with release assets on a PRIVATE GitHub repo (the enterprise mirror
// we build test releases on). A token on the /releases/download/ browser URL is not enough there —
// GitHub returns 404 for it regardless — so resolve the asset through the API and fetch it by id
// with an octet-stream Accept header. The API then redirects to object storage, which rejects a
// request carrying a second auth mechanism, so authenticate the first hop only and follow bare.
async function fetchArtifact(url) {
	const token = process.env['GITHUB_TOKEN'];
	const parsed = new URL(url);
	const release = token && parsed.hostname === 'github.com'
		? /^\/([^/]+)\/([^/]+)\/releases\/download\/([^/]+)\/(.+)$/.exec(parsed.pathname)
		: undefined;
	if (!release) {
		return fetch(url, { redirect: 'follow' });
	}
	const [, owner, repo, tag, file] = release;
	const meta = await fetch(`https://api.github.com/repos/${owner}/${repo}/releases/tags/${tag}`, {
		headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' }
	});
	if (!meta.ok) {
		throw new Error(`Failed to look up release ${tag} in ${owner}/${repo}: HTTP ${meta.status}`);
	}
	const wanted = decodeURIComponent(file);
	const asset = ((await meta.json()).assets ?? []).find(a => a.name === wanted);
	if (!asset) {
		throw new Error(`Release ${tag} in ${owner}/${repo} has no asset named '${wanted}'`);
	}
	const res = await fetch(asset.url, {
		headers: { Authorization: `Bearer ${token}`, Accept: 'application/octet-stream' },
		redirect: 'manual'
	});
	const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : undefined;
	return location ? fetch(location, { redirect: 'follow' }) : res;
}

async function hashAndSize(url, mirrorPath) {
	const res = await fetchArtifact(url);
	if (!res.ok || !res.body) {
		throw new Error(`Failed to download ${url}: HTTP ${res.status}`);
	}
	const hash = createHash('sha256');
	let size = 0;
	let out;
	if (mirrorPath) {
		mkdirSync(path.dirname(mirrorPath), { recursive: true });
		out = createWriteStream(mirrorPath);
	}
	for await (const chunk of Readable.fromWeb(res.body)) {
		hash.update(chunk);
		size += chunk.length;
		if (out && !out.write(chunk)) {
			await new Promise(resolve => out.once('drain', resolve));
		}
	}
	if (out) {
		await new Promise((resolve, reject) => {
			out.on('error', reject);
			out.end(resolve);
		});
	}
	return { sha256: hash.digest('hex'), sizeBytes: size };
}

async function hashLocalFile(filePath, mirrorPath) {
	const hash = createHash('sha256');
	let size = 0;
	for await (const chunk of createReadStream(filePath)) {
		hash.update(chunk);
		size += chunk.length;
	}
	if (mirrorPath) {
		mkdirSync(path.dirname(mirrorPath), { recursive: true });
		copyFileSync(filePath, mirrorPath);
	}
	return { sha256: hash.digest('hex'), sizeBytes: size };
}

async function main() {
	const args = parseArgs(process.argv.slice(2));
	const channel = args.channel || 'stable';
	const platform = args.platform;
	const arch = args.arch;
	const sequence = Number(args.sequence ?? 0);
	const noDownload = !!args['no-download'];

	if (!platform || !arch) {
		throw new Error('Missing required --platform and/or --arch');
	}

	const configPath = args.config || path.join(SCRIPT_DIR, 'update-manifest.config.json');
	const versionsPath = args.versions || path.join(SCRIPT_DIR, 'component-versions.properties');
	const config = JSON.parse(readFileSync(configPath, 'utf8'));
	const versions = readVersions(versionsPath);

	// Mirror mode: artifacts are re-hosted on the update bucket/CDN and the manifest points there.
	const artifactsBase = typeof args['artifacts-base'] === 'string' ? args['artifacts-base'].replace(/\/+$/, '') : '';
	const mirrorDir = typeof args['mirror-dir'] === 'string' ? args['mirror-dir'] : '';
	if (artifactsBase && !mirrorDir && !args['no-download']) {
		// A CDN URL in the manifest with no mirrored bytes to upload would 404 for every client.
		throw new Error('--artifacts-base requires --mirror-dir (or --no-download for structure checks)');
	}

	// Per-component source flavor overrides ("id=flavor,..."): mirror from the SAME source the
	// build bundled (e.g. wso2.ballerina=github when the build used ballerina_extension_source=
	// github), so the published artifact can never diverge from the packed one.
	const sourceFlavors = {};
	if (typeof args['source-flavors'] === 'string' && args['source-flavors']) {
		for (const pair of args['source-flavors'].split(',')) {
			const [id, flavor] = pair.split('=').map(s => s.trim());
			if (id && flavor) {
				sourceFlavors[id] = flavor;
			}
		}
	}

	const appVersion = args['app-version'] || versions['integrator.version'];
	const platformArch = `${platform}-${arch}`;

	const substitutionVars = {
		appVersion,
		ballerinaVersion: versions['ballerina.version'],
		icpVersion: versions['icp.version'],
		jreVersion: versions['ballerina.jre.version'],
		ballerinaPlatform: config.platformTokens?.ballerina?.[platformArch],
		jrePlatform: config.platformTokens?.jre?.[platformArch]
	};

	// A component's version comes from component-versions.properties (versionKey) or, for
	// components built in this repo (e.g. the WI extension), from their own package.json.
	const resolveVersion = component => {
		if (component.versionKey) {
			return versions[component.versionKey];
		}
		if (component.versionFromPackageJson) {
			return JSON.parse(readFileSync(path.join(REPO_ROOT, component.versionFromPackageJson), 'utf8')).version;
		}
		return undefined;
	};

	const components = [];
	for (const component of config.components) {
		// Components that only exist as a repo-local build artifact (no public source URL) can
		// only be published when mirroring is on. Without a CDN configured, skip them LOUDLY
		// rather than failing the whole manifest — the rest of the set still publishes.
		if (component.sourceFile && !artifactsBase) {
			process.stderr.write(`SKIPPING ${component.id}: needs --artifacts-base (no public source URL); it will not be offered as an update\n`);
			continue;
		}
		const version = resolveVersion(component);
		// Some upstreams tag a pre-release with a suffix but name the assets inside that release
		// after the base version — Ballerina's v2201.13.6-alpha2 ships
		// `ballerina-2201.13.6-swan-lake-linux.zip`. `{versionBase}` lets a template keep the full
		// version in the tag and drop the suffix in the filename. Only use it where the upstream is
		// known to name assets that way; assuming it everywhere would break the ones that don't.
		const versionBase = typeof version === 'string' ? version.split('-')[0] : version;
		// Fail rather than skip: a declared component that can't be rendered would otherwise
		// produce a signed-but-incomplete manifest (and a recommendedSet referencing it), which
		// the client would treat as authoritative. A missing version / unresolved URL is a
		// release-blocking configuration error.
		if (!version) {
			throw new Error(`Cannot render ${component.id}: no version (key '${component.versionKey ?? component.versionFromPackageJson}')`);
		}

		// Source: a public URL to fetch from, or a repo-local file (locally built artifacts).
		let sourceUrl;
		let sourceFile;
		if (component.sourceFile) {
			sourceFile = path.join(REPO_ROOT, substitute(component.sourceFile, { ...substitutionVars, version, versionBase }));
		} else {
			// 'marketplace' (or no flavor) is the default `url`; other flavors must be declared
			// in the component's `sources` map — fail loudly rather than silently publishing
			// from a different source than the build bundled.
			const flavor = sourceFlavors[component.id];
			let urlTemplate = component.url;
			if (flavor && flavor !== 'marketplace') {
				urlTemplate = component.sources?.[flavor];
				if (!urlTemplate) {
					throw new Error(`Cannot render ${component.id}: no source URL for flavor '${flavor}'`);
				}
			}
			sourceUrl = substitute(urlTemplate, { ...substitutionVars, version, versionBase });
			if (sourceUrl.includes('{')) {
				throw new Error(`Cannot render ${component.id}: unresolved URL placeholder in '${sourceUrl}'`);
			}
		}

		// Decode BEFORE basename: an encoded separator (..%2F) would otherwise survive
		// basename and decode into a traversal that escapes the mirror dir.
		const fileName = safeSegment(sourceFile
			? path.basename(sourceFile)
			: path.posix.basename(decodeURIComponent(new URL(sourceUrl).pathname)), 'file name');
		const relPath = `components/${safeSegment(component.id, 'component id')}/${safeSegment(version, 'version')}/${fileName}`;

		const artifact = {};
		if (artifactsBase) {
			artifact.url = `${artifactsBase}/${relPath}`;
		} else if (sourceUrl) {
			artifact.url = sourceUrl;
		} else {
			throw new Error(`Cannot render ${component.id}: sourceFile components require --artifacts-base (no public source URL)`);
		}
		if (noDownload) {
			artifact.sha256 = 'PLACEHOLDER_NO_DOWNLOAD';
			artifact.sizeBytes = 0;
		} else {
			const mirrorPath = artifactsBase ? path.join(mirrorDir, relPath) : undefined;
			const { sha256, sizeBytes } = sourceFile
				? await hashLocalFile(sourceFile, mirrorPath)
				: await hashAndSize(sourceUrl, mirrorPath);
			artifact.sha256 = sha256;
			artifact.sizeBytes = sizeBytes;
		}
		// Only a MIRRORED artifact can carry a signature of ours: the CI job cosigns everything under
		// the mirror dir and uploads `<file>.sig` next to it. A third-party source URL has no such
		// file, so promising one would make the client reject an artifact it can never verify.
		if (artifactsBase) {
			artifact.signature = { sigUrl: `${artifactsBase}/${relPath}.sig` };
		}

		const requires = component.requires
			? Object.fromEntries(Object.entries(component.requires).map(([k, v]) => [k, substitute(v, substitutionVars)]))
			: undefined;

		components.push({
			id: component.id,
			kind: component.kind,
			version,
			artifact,
			...(requires ? { requires } : {}),
			rollout: { percentage: 100 }
		});
	}

	// App installer (core-app update) — optional; only when an installer URL is supplied.
	// Mirrored to the bucket like every other artifact when --artifacts-base is set.
	let app;
	if (args['app-installer-url']) {
		const sourceUrl = args['app-installer-url'];
		const fileName = safeSegment(path.posix.basename(decodeURIComponent(new URL(sourceUrl).pathname)), 'installer file name');
		const relPath = `app/${safeSegment(appVersion, 'app version')}/${fileName}`;
		const installer = { url: artifactsBase ? `${artifactsBase}/${relPath}` : sourceUrl };
		if (noDownload) {
			installer.sha256 = 'PLACEHOLDER_NO_DOWNLOAD';
			installer.sizeBytes = 0;
		} else {
			const mirrorPath = artifactsBase ? path.join(mirrorDir, relPath) : undefined;
			const { sha256, sizeBytes } = await hashAndSize(sourceUrl, mirrorPath);
			installer.sha256 = sha256;
			installer.sizeBytes = sizeBytes;
		}
		if (artifactsBase) {
			installer.signature = { sigUrl: `${artifactsBase}/${relPath}.sig` };
		}
		app = { version: appVersion, minAutoUpdateFromVersion: args['app-min-version'] || undefined, installer };
		// The commit this build was produced from (product-integrator root sha). The update
		// server's Squirrel endpoint compares the mac client's commit against this.
		if (args['app-commit']) {
			app.commit = args['app-commit'];
		}
		// Squirrel.Mac (darwin): embed the URL of the editor-only .app zip so the update server
		// serves the /api/update/darwin* feed straight from this signed manifest — no separate
		// squirrel.json artifact. Prefer the mirrored CDN copy (uploaded by the mac build job to
		// artifacts/app/{version}/ with this exact name); fall back to an explicitly supplied URL
		// (e.g. the GitHub release asset) so mac updates are testable before a CDN exists.
		if (platform === 'darwin') {
			const zipName = `wso2-integrator-${safeSegment(appVersion, 'app version')}-${arch}-mac.zip`;
			if (artifactsBase) {
				app.squirrel = { url: `${artifactsBase}/app/${appVersion}/${zipName}` };
			} else if (typeof args['app-squirrel-url'] === 'string' && args['app-squirrel-url']) {
				app.squirrel = { url: args['app-squirrel-url'] };
			}
		}
	}

	// Only reference components that were actually emitted above, so the recommended set can
	// never point at a component missing from the manifest (e.g. one skipped for lack of a CDN).
	const emittedIds = new Set(components.map(c => c.id));
	const recommendedMembers = {};
	for (const component of config.components) {
		const version = resolveVersion(component);
		if (component.recommended && version && emittedIds.has(component.id)) {
			recommendedMembers[component.id] = version;
		}
	}

	const publishedAt = args['published-at'] || new Date().toISOString();
	const expiresDays = Number(args['expires-days'] ?? 90);
	const expiresAt = new Date(Date.parse(publishedAt) + expiresDays * 24 * 60 * 60 * 1000).toISOString();

	const manifest = {
		schemaVersion: 1,
		channel,
		platform,
		arch,
		sequence,
		publishedAt,
		expiresAt,
		...(app ? { app } : {}),
		components,
		recommendedSet: { name: `${channel}-${appVersion}`, members: recommendedMembers }
	};

	const json = JSON.stringify(manifest, null, 2);
	if (args.out) {
		writeFileSync(args.out, json + '\n', 'utf8');
		process.stderr.write(`Wrote ${args.out} (${components.length} components)\n`);
	} else {
		process.stdout.write(json + '\n');
	}
}

main().catch(err => {
	process.stderr.write(`generate-update-manifest failed: ${err.message}\n`);
	process.exit(1);
});
