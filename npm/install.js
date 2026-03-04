#!/usr/bin/env node
"use strict";

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

// Map Node platform/arch to Rust target triples
const PLATFORM_MAP = {
  "darwin-x64":   "x86_64-apple-darwin",
  "darwin-arm64": "aarch64-apple-darwin",
  "linux-x64":    "x86_64-unknown-linux-gnu",
  "linux-arm64":  "aarch64-unknown-linux-gnu",
  "win32-x64":    "x86_64-pc-windows-msvc",
};

const REPO = "mcplint/mcplint";

function main() {
  const platformKey = `${process.platform}-${process.arch}`;
  const target = PLATFORM_MAP[platformKey];

  if (!target) {
    console.error(`mcplint: unsupported platform: ${platformKey}`);
    console.error("Supported: " + Object.keys(PLATFORM_MAP).join(", "));
    process.exit(1);
  }

  const version = require("./package.json").version;
  const isWindows = process.platform === "win32";
  const ext = isWindows ? "zip" : "tar.gz";
  const binName = isWindows ? "mcplint.exe" : "mcplint";

  const url = `https://github.com/${REPO}/releases/download/v${version}/mcplint-${target}.${ext}`;

  const binDir = path.join(__dirname, "bin");
  fs.mkdirSync(binDir, { recursive: true });
  const binPath = path.join(binDir, binName);

  console.log(`mcplint: downloading ${target} binary...`);

  try {
    if (isWindows) {
      const tmpZip = path.join(binDir, "mcplint.zip");
      execSync(
        `powershell -Command "Invoke-WebRequest -Uri '${url}' -OutFile '${tmpZip}'"`,
        { stdio: "inherit" }
      );
      execSync(
        `powershell -Command "Expand-Archive -Path '${tmpZip}' -DestinationPath '${binDir}' -Force"`,
        { stdio: "inherit" }
      );
      fs.unlinkSync(tmpZip);
    } else {
      execSync(
        `curl -fsSL "${url}" | tar xz -C "${binDir}"`,
        { stdio: "inherit" }
      );
      fs.chmodSync(binPath, 0o755);
    }

    const ver = execSync(`"${binPath}" --version`, { encoding: "utf-8" }).trim();
    console.log(`mcplint: installed ${ver}`);
  } catch (err) {
    console.error(`mcplint: failed to download binary from ${url}`);
    console.error(err.message);
    console.error("");
    console.error("You can install manually:");
    console.error("  cargo install mcplint");
    process.exit(1);
  }
}

main();
