import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const MAX_RETRIES = 3;

export async function loadConfig(path) {
  const data = await readFile(path, "utf-8");
  return JSON.parse(data);
}

export function greet(name) {
  const safe = String(name).replace(/[<>&]/g, "");
  const el = document.createElement("p");
  el.textContent = safe;
  document.body.appendChild(el);
  return el;
}

// Function reference, not a string: no implied eval.
export function scheduleRefresh() {
  setTimeout(() => refresh(), 1000);
  setInterval(refresh, 5000);
}

// SHA-256 is fine; only md5/sha1 are flagged.
export function sha256hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

// Static template literal: no substitution, nothing dynamic.
export function staticQuery() {
  return db.query(`SELECT id, name FROM users WHERE active = 1`);
}

function refresh() {
  console.log("refresh", MAX_RETRIES);
}
