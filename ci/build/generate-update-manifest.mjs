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

// Writes the signed-statement source document next to a mirrored artifact. CI signs this file, not
// the artifact: a signature over bytes alone would prove only that WSO2 produced them, leaving a
// manifest free to offer an old signed artifact under a new version label. Binding id + version +
// digest (+ requires) into the signed document is what the client checks against the manifest's claim.
function writeStatement(mirrorPath, { id, version, sha256, sizeBytes, requires }) {
	const statement = { schemaVersion: 1, id, version, sha256, sizeBytes };
	if (requires && Object.keys(requires).length > 0) {
		statement.requires = requires;
	}
	const statementPath = `${mirrorPath}.statement.json`;
	writeFileSync(statementPath, JSON.stringify(statement, null, 2) + '\n');
	return statementPath;
}

async function main() {
	const args = parseArgs(process.argv.slice(2));
	const channel = args.channel || 'stable';
	const sequence = Number(args.sequence ?? 0);
	const noDownload = !!args['no-download'];

	const configPath = args.config || path.join(SCRIPT_DIR, 'update-manifest.config.json');
	const versionsPath = args.versions || path.join(SCRIPT_DIR, 'component-versions.properties');
	const config = JSON.parse(readFileSync(configPath, 'utf8'));
	const versions = readVersions(versionsPath);

	const targets = config.targets;
	if (!Array.isArray(targets) || targets.length === 0) {
		throw new Error('config.targets must list the platform-arch pairs to publish');
	}

	// Mirror mode: artifacts are re-hosted on the update bucket/CDN and the source points there.
	const artifactsBase = typeof args['artifacts-base'] === 'string' ? args['artifacts-base'].replace(/\/+$/, '') : '';
	const mirrorDir = typeof args['mirror-dir'] === 'string' ? args['mirror-dir'] : '';
	if (artifactsBase && !mirrorDir && !noDownload) {
		// A CDN URL with no mirrored bytes to upload would 404 for every client.
		throw new Error('--artifacts-base requires --mirror-dir (or --no-download for structure checks)');
	}

	// Per-component source flavor overrides ("id=flavor,..."): mirror from the SAME source the
	// build bundled, so the published artifact can never diverge from the packed one.
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
	const commonVars = {
		appVersion,
		ballerinaVersion: versions['ballerina.version'],
		icpVersion: versions['icp.version'],
		jreVersion: versions['ballerina.jre.version']
	};
	const varsFor = target => ({
		...commonVars,
		ballerinaPlatform: config.platformTokens?.ballerina?.[target],
		jrePlatform: config.platformTokens?.jre?.[target]
	});

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

	// Download, hash, mirror and describe each DISTINCT artifact exactly once. Platform-independent
	// artifacts (a VSIX) resolve to the same URL for every target, and re-fetching them per target
	// would multiply a release's CI time and bandwidth for identical bytes.
	const resolved = new Map();
	const resolveArtifact = async ({ relPath, sourceUrl, sourceFile, statement }) => {
		const existing = resolved.get(relPath);
		if (existing) {
			return existing;
		}
		const entry = { url: artifactsBase ? `${artifactsBase}/${relPath}` : sourceUrl };
		if (!entry.url) {
			throw new Error(`Cannot render ${statement.id}: no public source URL; --artifacts-base is required`);
		}
		if (noDownload) {
			entry.sha256 = 'PLACEHOLDER_NO_DOWNLOAD';
			entry.sizeBytes = 0;
		} else {
			const mirrorPath = artifactsBase ? path.join(mirrorDir, relPath) : undefined;
			const { sha256, sizeBytes } = sourceFile
				? await hashLocalFile(sourceFile, mirrorPath)
				: await hashAndSize(sourceUrl, mirrorPath);
			entry.sha256 = sha256;
			entry.sizeBytes = sizeBytes;
		}
		// Only a MIRRORED artifact can carry a statement of ours: CI cosigns everything under the
		// mirror dir. A third-party source URL has none, so promising one would make the client
		// reject an artifact it could never verify.
		if (artifactsBase) {
			entry.signature = {
				statementUrl: `${artifactsBase}/${relPath}.statement.json`,
				sigUrl: `${artifactsBase}/${relPath}.statement.json.sig`
			};
			if (!noDownload) {
				writeStatement(path.join(mirrorDir, relPath), {
					...statement,
					sha256: entry.sha256,
					sizeBytes: entry.sizeBytes
				});
			}
		}
		resolved.set(relPath, entry);
		return entry;
	};

	const components = [];
	for (const component of config.components) {
		// Components that only exist as a repo-local build artifact (no public source URL) can only
		// be published when mirroring is on. Skip LOUDLY rather than failing the whole document.
		if (component.sourceFile && !artifactsBase) {
			process.stderr.write(`SKIPPING ${component.id}: needs --artifacts-base (no public source URL); it will not be offered as an update\n`);
			continue;
		}
		const version = resolveVersion(component);
		// Fail rather than skip: a declared component that cannot be rendered would otherwise
		// produce a signed-but-incomplete document, which the server would serve as authoritative.
		if (!version) {
			throw new Error(`Cannot render ${component.id}: no version (key '${component.versionKey ?? component.versionFromPackageJson}')`);
		}
		const requires = component.requires
			? Object.fromEntries(Object.entries(component.requires).map(([k, v]) => [k, substitute(v, commonVars)]))
			: undefined;

		const perTarget = {};
		for (const target of targets) {
			// Some upstreams tag a pre-release with a suffix but name the assets inside it after the
			// base version — Ballerina's v2201.13.6-alpha2 ships ballerina-2201.13.6-swan-lake-*.zip.
			// {versionBase} keeps the full version in the tag and drops the suffix in the filename.
			const versionBase = typeof version === 'string' ? version.split('-')[0] : version;
			const vars = { ...varsFor(target), version, versionBase };
			let sourceUrl;
			let sourceFile;
			if (component.sourceFile) {
				sourceFile = path.join(REPO_ROOT, substitute(component.sourceFile, vars));
			} else {
				// 'marketplace' (or no flavor) is the default `url`; other flavors must be declared
				// in `sources` — fail loudly rather than publishing a different source than was built.
				const flavor = sourceFlavors[component.id];
				let urlTemplate = component.url;
				if (flavor && flavor !== 'marketplace') {
					urlTemplate = component.sources?.[flavor];
					if (!urlTemplate) {
						throw new Error(`Cannot render ${component.id}: no source URL for flavor '${flavor}'`);
					}
				}
				sourceUrl = substitute(urlTemplate, vars);
				if (sourceUrl.includes('{')) {
					throw new Error(`Cannot render ${component.id} for ${target}: unresolved URL placeholder in '${sourceUrl}'`);
				}
			}
			// Decode BEFORE basename: an encoded separator (..%2F) would otherwise survive basename
			// and decode into a traversal that escapes the mirror dir.
			const fileName = safeSegment(sourceFile
				? path.basename(sourceFile)
				: path.posix.basename(decodeURIComponent(new URL(sourceUrl).pathname)), 'file name');
			const relPath = `components/${safeSegment(component.id, 'component id')}/${safeSegment(version, 'version')}/${fileName}`;
			perTarget[target] = await resolveArtifact({
				relPath,
				sourceUrl,
				sourceFile,
				statement: { id: component.id, version, requires }
			});
		}

		components.push({
			id: component.id,
			kind: component.kind,
			version,
			...(requires ? { requires } : {}),
			rollout: { percentage: Number(component.rolloutPercentage ?? 100) },
			recommended: !!component.recommended,
			targets: perTarget
		});
	}

	// Core-app entry. `appliesTo` is a range over the CLIENT's CURRENT version, which is how one
	// document serves several release lines: publish 5.1.z with appliesTo ">=5.1.0 <5.2.0" and a
	// 5.2.x client is simply not matched by it.
	const apps = [];
	const releaseBase = typeof args['app-release-base'] === 'string' ? args['app-release-base'].replace(/\/+$/, '') : '';
	if (releaseBase || artifactsBase) {
		const installerNames = config.app?.installers ?? {};
		const squirrelNames = config.app?.squirrel ?? {};
		const perTarget = {};
		for (const target of targets) {
			const installerName = installerNames[target];
			if (!installerName) {
				continue; // no core-app installer published for this target
			}
			const fileName = safeSegment(substitute(installerName, { version: appVersion, appVersion }), 'installer file name');
			const relPath = `app/${safeSegment(appVersion, 'app version')}/${fileName}`;
			const entry = {
				installer: await resolveArtifact({
					relPath,
					sourceUrl: releaseBase ? `${releaseBase}/${fileName}` : undefined,
					statement: { id: 'app', version: appVersion }
				})
			};
			// Squirrel.Mac payload: the editor-only .app zip. Its provenance is macOS code signing,
			// which Squirrel enforces itself, so it carries a URL only.
			const squirrelName = squirrelNames[target];
			if (squirrelName) {
				const zip = safeSegment(substitute(squirrelName, { version: appVersion, appVersion }), 'squirrel file name');
				entry.squirrel = { url: `${artifactsBase || releaseBase}/${artifactsBase ? `app/${appVersion}/${zip}` : zip}` };
			}
			perTarget[target] = entry;
		}
		if (Object.keys(perTarget).length > 0) {
			apps.push({
				version: appVersion,
				...(args['app-commit'] ? { commit: args['app-commit'] } : {}),
				...(args['app-applies-to'] ? { appliesTo: args['app-applies-to'] } : {}),
				rollout: { percentage: Number(args['app-rollout'] ?? 100) },
				targets: perTarget
			});
		}
	}

	const publishedAt = args['published-at'] || new Date().toISOString();
	const expiresDays = Number(args['expires-days'] ?? 90);
	const expiresAt = new Date(Date.parse(publishedAt) + expiresDays * 24 * 60 * 60 * 1000).toISOString();

	const source = {
		schemaVersion: 2,
		channel,
		sequence,
		publishedAt,
		expiresAt,
		apps,
		components
	};

	const json = JSON.stringify(source, null, 2);
	if (args.out) {
		writeFileSync(args.out, json + '\n', 'utf8');
		process.stderr.write(`Wrote ${args.out} (${components.length} components x ${targets.length} targets, ${apps.length} app entries)\n`);
	} else {
		process.stdout.write(json + '\n');
	}
}

main().catch(err => {
	process.stderr.write(`generate-update-source failed: ${err.message}\n`);
	process.exit(1);
});
