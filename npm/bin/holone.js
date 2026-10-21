#!/usr/bin/env node
'use strict';

// Thin launcher for the Go binary installed by postinstall.

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const exe = process.platform === 'win32' ? 'holone.exe' : 'holone';
const bin = path.join(__dirname, exe);

if (!fs.existsSync(bin)) {
  console.error('holone binary not found at ' + bin);
  console.error('reinstall the package or run: npm rebuild holone');
  process.exit(1);
}

const child = spawn(bin, process.argv.slice(2), {
  stdio: 'inherit',
  env: process.env,
});

child.on('error', (err) => {
  console.error('failed to start holone: ' + err.message);
  process.exit(1);
});

child.on('exit', (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code === null ? 1 : code);
});
