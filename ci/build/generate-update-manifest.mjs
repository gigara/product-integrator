#!/usr/bin/env node
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Renders a WSO2 Integrator update manifest (see docs/update-mechanism-design.md §4.2) for a
// given (channel, platform, arch) from ci/build/update-manifest.config.json and
// ci/build/component-versions.properties, computing each artifact's sha256 + size by
// downloading it. The output is uploaded (and cosign-signed) by the publish-update-manifest CI job.
//
// Usage:
//   node ci/build/generate-update-manifest.mjs \
//     --channel stable --platform darwin --arch arm64 --sequence 42 \
//     --app-version 5.0.1.0 [--app-installer-url URL] [--out manifest.json] [--no-download]
//
// --no-download emits placeholder hashes (structure-only; for local validation, not for release).

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { Readable } from 'node:stream';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));

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

async function hashAndSize(url) {
	const res = await fetch(url, { redirect: 'follow' });
	if (!res.ok || !res.body) {
		throw new Error(`Failed to download ${url}: HTTP ${res.status}`);
	}
	const hash = createHash('sha256');
	let size = 0;
	for await (const chunk of Readable.fromWeb(res.body)) {
		hash.update(chunk);
		size += chunk.length;
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

	const components = [];
	for (const component of config.components) {
		const version = versions[component.versionKey];
		// Fail rather than skip: a declared component that can't be rendered would otherwise
		// produce a signed-but-incomplete manifest (and a recommendedSet referencing it), which
		// the client would treat as authoritative. A missing version / unresolved URL is a
		// release-blocking configuration error.
		if (!version) {
			throw new Error(`Cannot render ${component.id}: no version for key '${component.versionKey}'`);
		}
		const url = substitute(component.url, { ...substitutionVars, version });
		if (url.includes('{')) {
			throw new Error(`Cannot render ${component.id}: unresolved URL placeholder in '${url}'`);
		}

		const artifact = { url };
		if (noDownload) {
			artifact.sha256 = 'PLACEHOLDER_NO_DOWNLOAD';
			artifact.sizeBytes = 0;
		} else {
			const { sha256, sizeBytes } = await hashAndSize(url);
			artifact.sha256 = sha256;
			artifact.sizeBytes = sizeBytes;
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

	// App installer (full-app update) — optional; only when an installer URL is supplied.
	let app;
	if (args['app-installer-url']) {
		const installer = { url: args['app-installer-url'] };
		if (noDownload) {
			installer.sha256 = 'PLACEHOLDER_NO_DOWNLOAD';
			installer.sizeBytes = 0;
		} else {
			const { sha256, sizeBytes } = await hashAndSize(args['app-installer-url']);
			installer.sha256 = sha256;
			installer.sizeBytes = sizeBytes;
		}
		app = { version: appVersion, minAutoUpdateFromVersion: args['app-min-version'] || undefined, installer };
	}

	const recommendedMembers = {};
	for (const component of config.components) {
		if (component.recommended && versions[component.versionKey]) {
			recommendedMembers[component.id] = versions[component.versionKey];
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
