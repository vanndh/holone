#!/usr/bin/env node
'use strict';

// postinstall: download the holone release binary for this platform, verify its
// SHA-256 against the release's SHA256SUMS.txt, and place it in bin/.
// Only Node.js stdlib is used so `npm i -g holone` needs no dependencies.

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');

const REPO = 'vanndh/holone';
const DEFAULT_VERSION = '0.4.2';
const MAX_REDIRECTS = 5;

function fail(message) {
  console.error(message);
  process.exit(1);
}

function platformInfo() {
  const osMap = { win32: 'windows', darwin: 'darwin', linux: 'linux' };
  const archMap = { x64: 'amd64', arm64: 'arm64' };
  const goos = osMap[process.platform];
  const goarch = archMap[process.arch];
  if (!goos) {
    fail(`ERROR: unsupported platform: ${process.platform} (holone supports win32, darwin, linux)`);
  }
  if (!goarch) {
    fail(`ERROR: unsupported architecture: ${process.arch} (holone supports x64 and arm64)`);
  }
  return { goos, goarch, ext: goos === 'windows' ? '.exe' : '' };
}

function download(url, dest, redirects) {
  const left = redirects === undefined ? MAX_REDIRECTS : redirects;
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'holone-npm-installer' } }, (res) => {
      const status = res.statusCode || 0;
      if (status >= 300 && status < 400 && res.headers.location) {
        res.resume();
        if (left <= 0) {
          reject(new Error(`too many redirects for ${url}`));
          return;
        }
        const next = new URL(res.headers.location, url).toString();
        download(next, dest, left - 1).then(resolve, reject);
        return;
      }
      if (status !== 200) {
        res.resume();
        reject(new Error(`HTTP ${status} for ${url}`));
        return;
      }
      const file = fs.createWriteStream(dest);
      file.on('error', reject);
      file.on('finish', () => file.close((err) => (err ? reject(err) : resolve())));
      res.on('error', reject);
      res.pipe(file);
    });
    req.on('error', reject);
    req.setTimeout(60000, () => req.destroy(new Error(`timeout downloading ${url}`)));
  });
}

function sha256(file) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(file);
    stream.on('error', reject);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

function expectedHash(sumsText, asset) {
  for (const raw of sumsText.split(/\r?\n/)) {
    const parts = raw.trim().split(/\s+/);
    if (parts.length < 2) continue;
    const name = parts[1].replace(/^\*/, '');
    if (name === asset) return parts[0].toLowerCase();
  }
  return null;
}

async function main() {
  if (process.env.HOLONE_NPM_SKIP_DOWNLOAD === '1') {
    console.log('holone: HOLONE_NPM_SKIP_DOWNLOAD=1, skipping binary download');
    return;
  }

  const { goos, goarch, ext } = platformInfo();
  const version = (process.env.HOLONE_VERSION || DEFAULT_VERSION).replace(/^v/, '');
  const base = `https://github.com/${REPO}/releases/download/v${version}`;
  const asset = `holone-${goos}-${goarch}${ext}`;

  const binDir = path.join(__dirname, 'bin');
  const binPath = path.join(binDir, `holone${ext}`);
  const tmpPath = path.join(os.tmpdir(), `holone-${process.pid}-${Date.now()}${ext}`);
  const sumsPath = path.join(os.tmpdir(), `holone-sums-${process.pid}-${Date.now()}.txt`);

  fs.mkdirSync(binDir, { recursive: true });

  console.log(`holone: downloading ${asset} (v${version})`);
  try {
    await download(`${base}/${asset}`, tmpPath);
    await download(`${base}/SHA256SUMS.txt`, sumsPath);
  } catch (err) {
    cleanup([tmpPath, sumsPath]);
    fail(`ERROR: failed to download holone ${version}: ${err.message}`);
  }

  let sumsText;
  try {
    sumsText = fs.readFileSync(sumsPath, 'utf8');
  } catch (err) {
    cleanup([tmpPath, sumsPath]);
    fail(`ERROR: failed to read SHA256SUMS.txt: ${err.message}`);
  }

  const expected = expectedHash(sumsText, asset);
  if (!expected) {
    cleanup([tmpPath, sumsPath]);
    fail('ERROR: downloaded holone binary failed integrity verification (no SHA-256 entry for ' + asset + ')');
  }

  let actual;
  try {
    actual = await sha256(tmpPath);
  } catch (err) {
    cleanup([tmpPath, sumsPath]);
    fail(`ERROR: failed to hash downloaded binary: ${err.message}`);
  }

  if (actual !== expected) {
    cleanup([tmpPath, sumsPath]);
    fail(`ERROR: downloaded holone binary failed integrity verification (expected ${expected}, got ${actual})`);
  }

  fs.copyFileSync(tmpPath, binPath);
  if (process.platform !== 'win32') {
    fs.chmodSync(binPath, 0o755);
  }
  cleanup([tmpPath, sumsPath]);
  console.log(`holone: verified sha256 ${actual}`);
}

function cleanup(files) {
  for (const f of files) {
    try {
      fs.unlinkSync(f);
    } catch (_) {
      // already gone
    }
  }
}

main().catch((err) => {
  fail(`ERROR: ${err && err.message ? err.message : err}`);
});
