#!/usr/bin/env node
"use strict";

const { execFileSync } = require("child_process");
const path = require("path");

const binName = process.platform === "win32" ? "mcplint.exe" : "mcplint";
const binPath = path.join(__dirname, binName);

try {
  execFileSync(binPath, process.argv.slice(2), { stdio: "inherit" });
} catch (err) {
  if (err.status != null) {
    process.exit(err.status);
  }
  console.error("mcplint: binary not found. Try reinstalling: npm install -g @mcplint/cli");
  process.exit(1);
}
