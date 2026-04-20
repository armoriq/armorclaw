#!/usr/bin/env node
import { cpSync, mkdirSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

const dest = process.env.OPENCLAW_EXT_DIR
  ? resolve(process.env.OPENCLAW_EXT_DIR)
  : join(homedir(), ".openclaw", "extensions", "armorclaw");

const src = resolve("dist");
const destDist = join(dest, "dist");

rmSync(destDist, { recursive: true, force: true });
mkdirSync(dest, { recursive: true });
cpSync(src, destDist, { recursive: true });

console.log(`Installed ${src} -> ${destDist}`);
