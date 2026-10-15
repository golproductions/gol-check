// Check plugin launcher. Copyright (c) 2026 GOLProductions. All rights reserved.
//
// The plugin's only code. It finds the person's GOL API Key, makes sure the
// Check gate is on this machine (downloading it once, SHA-256 checked, the way
// the installer does), then hands the hook's input to the gate unchanged and
// returns the gate's answer. Check's logic lives in the gate and on the server.
//
// It never blocks on its own failure: some hosts (Copilot) deny the action when
// a hook crashes or exits non-zero, so any error here exits 0 (go ahead).
import { existsSync, mkdirSync, writeFileSync, renameSync, unlinkSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";

const BASE = "https://triage.golproductions.com";
const home = process.env.CHECK_TEST_HOME || homedir();
const dir = join(home, ".check");
const gate = join(dir, "check-hook.mjs");

// Claude Code: the key comes only from the plugin's own setting (entered at
// install, kept in Claude Code's secure storage), never from the machine.
function keyOf() {
  return (process.env.CLAUDE_PLUGIN_OPTION_GOL_API_KEY || "").trim();
}

// The gate is signed off the server (Ed25519); this is the public half.
const GATE_PUBKEY = "MCowBQYDK2VwAyEAvxzQMczyQqAvTLEBEZWR9SMUECPlGXc0JOyqC7FVh0o=";
function signedByGol(body, sigB64) {
  try { return !!sigB64 && cryptoVerify(null, body, createPublicKey({ key: Buffer.from(GATE_PUBKEY, "base64"), format: "der", type: "spki" }), Buffer.from(sigB64, "base64")); } catch { return false; }
}

function say(line) { try { process.stderr.write("check: " + line + "\n"); } catch {} }

async function fetchGate(key) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 15000);
  try {
    const r = await fetch(BASE + "/install-hook", { method: "POST", headers: { "X-GOL-CLIENT-ID": key, "User-Agent": "c/plugin" }, signal: ac.signal });
    if (!r.ok) { say(r.status === 401 || r.status === 403 ? "that GOL API Key wasn't accepted. Check it at https://golproductions.com/console" : "couldn't download Check (server said " + r.status + "). Actions go ahead unchecked."); return false; }
    const want = (r.headers.get("x-hook-sha256") || "").toLowerCase();
    const body = Buffer.from(await r.arrayBuffer());
    if (!want || createHash("sha256").update(body).digest("hex") !== want) { say("the downloaded gate didn't match its fingerprint, so it wasn't used."); return false; }
    if (!signedByGol(body, r.headers.get("x-hook-sig") || "")) { say("the downloaded gate's signature didn't verify, so it wasn't used. Actions go ahead unchecked."); return false; }
    mkdirSync(dir, { recursive: true });
    const tmp = gate + ".new.mjs";
    writeFileSync(tmp, body);
    if (spawnSync(process.execPath, ["--check", tmp], { windowsHide: true }).status !== 0) { try { unlinkSync(tmp); } catch {} return false; }
    renameSync(tmp, gate);
    return true;
  } catch { say("couldn't reach Check's server. Actions go ahead unchecked."); return false; }
  finally { clearTimeout(t); }
}

async function main() {
  let input = "";
  for await (const c of process.stdin) input += c;
  const key = keyOf();
  if (!key) { say("add your GOL API Key in the plugin's settings to turn Check on (from https://golproductions.com/console). Until then, actions go ahead unchecked."); return 0; }
  if (!existsSync(gate) && !(await fetchGate(key))) return 0;
  const env = { ...process.env, GOL_API_KEY: key };
  const r = spawnSync(process.execPath, [gate], { input, env, encoding: "utf8", timeout: 90000, windowsHide: true, maxBuffer: 16 * 1024 * 1024 });
  if (process.env.CHECK_PLUGIN_TRACE) { try { const { appendFileSync } = await import("node:fs"); appendFileSync(process.env.CHECK_PLUGIN_TRACE, JSON.stringify({ input: input.slice(0, 600), status: r.status, stdout: String(r.stdout || "").slice(0, 400), stderr: String(r.stderr || "").slice(0, 300) }) + "\n"); } catch {} }
  if (r.error || r.status === null) return 0;
  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);
  return r.status === 2 ? 2 : 0;
}

main().then((code) => process.exit(code), () => process.exit(0));
