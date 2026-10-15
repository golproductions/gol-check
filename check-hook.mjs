#!/usr/bin/env node
// Copyright (c) 2026 GOL Productions. All rights reserved. Proprietary and confidential.
//
// CHECK — HOOK ENTRYPOINT (PreToolUse)
//
// The tool call gate. Fires before every Bash / PowerShell / Write / Edit /
// NotebookEdit invocation across supported agents. Reads the hook payload on
// stdin, judges the write or the command, and writes a hook-shaped verdict on
// stdout. Never exits non-zero on a fail-open path.
//
// This file contains NOTHING but hook-time logic. Install / uninstall / status /
// billing UI live in the CLI (dist/index.js) and never load here. The split
// exists so a customer disk holds only what hook events actually require.
//
// FAIL POSTURE: any failure passes the command through with a warning. Never
// blocks. Only a measurement may deny.

import { readFileSync, writeFileSync, mkdirSync, existsSync, appendFileSync, unlinkSync, readdirSync, statSync, mkdtempSync, rmSync, readlinkSync, renameSync, lstatSync, statfsSync } from "node:fs";
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { spawnSync, spawn } from "node:child_process";
import { join, dirname, basename, win32 as pathWin32, posix as pathPosix } from "node:path";
import { homedir, platform, tmpdir } from "node:os";

const VERSION = "5.0.0";
const API = "https://triage.golproductions.com/preflight";
const BASE = API.replace(/\/preflight$/, "");
// The key, as Claude Code hands it to this hook: ${user_config.gol_api_key} in its arguments.
// An option that was never set arrives unsubstituted, and counts as no key.
const CLIENT_ID_ENV = ((a) => (typeof a === "string" && !a.includes("${") ? a.trim() : ""))(process.argv[2]);
// Gate updates are signed off the server (Ed25519); this is the public half.
// An update without a valid signature is never used, so reaching the server
// alone can't put code on anyone's machine.
const GATE_PUBKEY = "MCowBQYDK2VwAyEAvxzQMczyQqAvTLEBEZWR9SMUECPlGXc0JOyqC7FVh0o=";
function signedByGol(body, sigB64) {
  try { return !!sigB64 && cryptoVerify(null, body, createPublicKey({ key: Buffer.from(GATE_PUBKEY, "base64"), format: "der", type: "spki" }), Buffer.from(sigB64, "base64")); } catch { return false; }
}

// The key file is the fallback for tools that don't pass env to hooks (Cursor,
// Gemini). Env wins when set. .claude/settings.json env is the last fallback.
// Which package ecosystems this machine has repointed away from the public
// registry. The server can only ask registry.npmjs.org, pypi.org and friends.
// If npm here resolves against Artifactory, Verdaccio or a private scope, a
// public 404 is not absence, it is the wrong registry answering a question it
// was never asked, and a real package gets denied as a fabrication. The
// machine is the only authority on where it installs from, so it says so and
// the server abstains for those ecosystems.
//
// Over-reporting is safe: it costs a check. Under-reporting is a false denial.
// So any non-default registry line marks the whole ecosystem, scoped or not.
function customRegistries() {
  const hits = new Set();
  const home = (() => { try { return homedir(); } catch { return null; } })();
  const read = (p) => { try { return existsSync(p) ? readFileSync(p, "utf8") : null; } catch { return null; } };
  const env = (k) => { const v = process.env[k]; return typeof v === "string" && v.trim() ? v.trim() : null; };
  const hostOf = (u) => { try { return new URL(/^\/\//.test(u) ? "https:" + u : u).host.toLowerCase(); } catch { return null; } };
  const foreign = (u, ok) => { const h = hostOf(u); return h !== null && !ok.some(d => h === d || h.endsWith("." + d)); };

  // Config that lives beside the project, found the way the tools find it:
  // nearest first, walking up. Bounded, because a hook is on the hot path.
  const upward = (name) => {
    const found = [];
    let dir; try { dir = process.cwd(); } catch { return found; }
    for (let i = 0; i < 6 && dir; i++) {
      const c = read(join(dir, name));
      if (c !== null) found.push(c);
      const up = dirname(dir);
      if (up === dir) break;
      dir = up;
    }
    return found;
  };
  const lines = (body) => body.split(/\r?\n/);

  try {
    // npm, and with it npx, yarn and pnpm: they share .npmrc and the id "npm".
    const npmrc = [...upward(".npmrc"), home ? read(join(home, ".npmrc")) : null].filter(Boolean);
    const npmEnv = env("npm_config_registry") || env("NPM_CONFIG_REGISTRY");
    let npmCustom = npmEnv !== null && foreign(npmEnv, ["registry.npmjs.org"]);
    for (const body of npmrc) {
      for (const line of lines(body)) {
        const m = line.match(/^\s*(?:@[^\s:=]+:)?registry\s*=\s*(\S+)/i);
        if (m && foreign(m[1], ["registry.npmjs.org"])) npmCustom = true;
      }
    }
    if (npmCustom) hits.add("npm");

    // pip. PyPI serves metadata from pypi.org and files from pythonhosted.
    const pipFiles = [
      ...upward("pip.conf"), ...upward("pip.ini"),
      home ? read(join(home, ".pip", "pip.conf")) : null,
      home ? read(join(home, ".config", "pip", "pip.conf")) : null,
      process.env.APPDATA ? read(join(process.env.APPDATA, "pip", "pip.ini")) : null,
    ].filter(Boolean);
    const pipEnv = env("PIP_INDEX_URL") || env("PIP_EXTRA_INDEX_URL") || env("UV_INDEX_URL");
    let pipCustom = pipEnv !== null && foreign(pipEnv, ["pypi.org", "pythonhosted.org"]);
    for (const body of pipFiles) {
      for (const line of lines(body)) {
        const m = line.match(/^\s*(?:extra-)?index-url\s*=\s*(\S+)/i);
        if (m && foreign(m[1], ["pypi.org", "pythonhosted.org"])) pipCustom = true;
      }
    }
    if (pipCustom) hits.add("pypi");

    // cargo. A mirrored crates.io is a [source] replacement and an alternative
    // registry is a [registries] table. Either way the name this machine
    // resolves is not the name crates.io would answer for.
    const cargo = [...upward(join(".cargo", "config.toml")), ...upward(join(".cargo", "config")),
      home ? read(join(home, ".cargo", "config.toml")) : null,
      home ? read(join(home, ".cargo", "config")) : null].filter(Boolean);
    if (env("CARGO_REGISTRY_DEFAULT") || env("CARGO_REGISTRIES_CRATES_IO_INDEX") ||
        cargo.some(b => /replace-with/i.test(b) || /^\s*\[registries\./mi.test(b))) hits.add("cargo");

    // gem. GEM_HOST and GEM_SOURCE repoint pushes and pulls, and a :sources:
    // block in .gemrc replaces the default list outright.
    const gemrc = home ? read(join(home, ".gemrc")) : null;
    if (env("GEM_SOURCE") || env("GEM_HOST") ||
        (gemrc !== null && /^\s*:sources:/m.test(gemrc))) hits.add("gem");

    // nuget. Any packageSources entry pointing off nuget.org means restore
    // resolves somewhere this worker cannot see.
    for (const body of [...upward("NuGet.Config"), ...upward("nuget.config"),
         process.env.APPDATA ? read(join(process.env.APPDATA, "NuGet", "NuGet.Config")) : null].filter(Boolean)) {
      for (const m of body.matchAll(/value\s*=\s*"([^"]+)"/gi)) {
        if (/^https?:/i.test(m[1]) && foreign(m[1], ["nuget.org"])) hits.add("nuget");
      }
    }

    // composer. A repositories block is how a project points at a private
    // Satis or Private Packagist.
    for (const body of [...upward("composer.json"),
         home ? read(join(home, ".composer", "config.json")) : null,
         home ? read(join(home, ".config", "composer", "config.json")) : null].filter(Boolean)) {
      try { if (JSON.parse(body).repositories) hits.add("composer"); } catch {}
    }

    // brew has no equivalent: formulae.brew.sh is fixed, and tap names fail the
    // ecosystem name check and abstain already.
  } catch { /* measurement failed: say nothing, which reads as unknown */ }

  return [...hits];
}

// Inside a plugin: the plugin's own setting, as Claude Code passes it. Nothing else.
function getClientId() { return CLIENT_ID_ENV; }

// --- REDACTION -------------------------------------------------------------
//
// Nothing leaves this machine carrying identity or a credential. Runs before
// the request is built, not at the edge. Every replacement is a single token;
// every pattern matches something that cannot be a command word.

const REDACTIONS = [
  [/\b(?:sk|pk|rk)_(?:live|test|prod)?_?[A-Za-z0-9]{16,}\b/g, "[SECRET]"],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, "[GITHUB_TOKEN]"],
  [/\bnpm_[A-Za-z0-9]{30,}\b/g, "[NPM_TOKEN]"],
  [/\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g, "[SLACK_TOKEN]"],
  [/\bAKIA[0-9A-Z]{16}\b/g, "[AWS_KEY]"],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, "[GOOGLE_KEY]"],
  [/\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "[JWT]"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[PRIVATE_KEY]"],
  [/\b(?:Bearer|Authorization:\s*Bearer)\s+[A-Za-z0-9._-]{20,}/gi, "Bearer [TOKEN]"],
  // The last label of a mail domain is letters. Without that, `lodash@99.99.99`
  // read as an email and the version never reached the registry check (10 Oct).
  [/\b[\w.+-]+@(?:[\w-]+\.)+[A-Za-z]{2,}\b/g, "[EMAIL]"],
  [/\b(?:\d[ -]?){13,19}\b/g, "[CARD_LIKE]"],
];

function redact(s) {
  let out = String(s ?? "");
  for (const [re, tag] of REDACTIONS) out = out.replace(re, tag);
  return out;
}

function redactPath(p) {
  let out = redact(String(p ?? ""));
  try {
    const home = homedir();
    if (home && out.startsWith(home)) out = "~" + out.slice(home.length);
  } catch {}
  const user = process.env.USER || process.env.USERNAME;
  if (user && user.length > 2) {
    out = out.split(user).join("[USER]");
  }
  return out;
}

// --- SHELL SYNTAX (bash / PowerShell) --------------------------------------

function bashPath() {
  if (platform() !== "win32") return "bash";
  const candidates = [
    process.env.CLAUDE_CODE_GIT_BASH_PATH,
    "C:/Program Files/Git/bin/bash.exe",
    "C:/Program Files/Git/usr/bin/bash.exe",
    "C:/Program Files (x86)/Git/bin/bash.exe",
  ].filter(Boolean);
  for (const c of candidates) { try { if (existsSync(c)) return c; } catch {} }
  return null;
}

// --- THE ROD: the machine lexes the command --------------------------------
//
// The server used to split commands with its own model of bash, then asked the
// machine about words that were never commands: `x="a b"` put `b"` up for a PATH
// lookup, and a quoted "manual probe test" put `probe` (field false blocks,
// 22 Sep). Now the shell that would run the command names its words, and the
// server holds no grammar of its own.
//   bash: walks the command with every simple command skipped (extdebug DEBUG
//         trap, restricted mode, nothing expanded) and splits each one's words.
//   PowerShell: its own parser's AST, the same one the syntax check uses.
// A command the machine could not read is sent as null, and the server is
// silent on it. Measured 24 Sep: 22 cases, zero side effects, ~50 ms.
const ROD_SH = [
  "# THE ROD (lexer): bash itself names the words of every simple command it would run,",
  "# and runs none of them. Input: the command in $GOL_ROD_SRC. Output on stdout: one record per",
  "# simple command, \\x1d + words separated by \\x1f + \\x1e. A record of \\x01 means \"bash reached a",
  "# command here but its words could not be read\": the gate stays silent on it. A final \\x1d\\x02\\x1e",
  "# means bash stopped walking early (loop cap): commands after that point were not seen.",
  "#   extdebug + a DEBUG trap returning 1  -> bash skips each simple command instead of running it",
  "#   set -T                               -> the trap follows into functions and subshells",
  "#   set -r                               -> restricted: output redirection is refused, never performed",
  "# Compound headers (for/case/select/[[/((), which run no program, are allowed so bash walks into",
  "# loop bodies. Nothing is ever expanded inside the trap: $ ` ( ) < > & are neutralised before",
  "# bash splits the words, so the split is pure lexing and cannot run anything. (Measured: letting",
  "# $(...) expand here ran `touch` for real, because the trap does not fire inside a substitution",
  "# started by the trap itself.) Commands inside $(...) are therefore not seen: silence, not a guess.",
  "declare -A __rod_seen=()",
  "__rod_n=0",
  "__rod_trap() {",
  "  local c=$BASH_COMMAND",
  "  __rod_n=$((__rod_n + 1)); if (( __rod_n > 400 )); then printf '\\x1d\\x02\\x1e'; exit 0; fi",
  "  [[ $c == __rod_body ]] && return 0      # the one call that enters the command",
  "  case $c in 'for '*|'case '*|'select '*|'[['*|'(('*) return 0 ;; esac",
  "  # ${...} holding whitespace would be split below: unreadable, say so.",
  "  if [[ $c =~ \\$\\{[^}]*[[:space:]] ]]; then printf '\\x1d\\x01\\x1e'; return 1; fi",
  "  # After this, the text holds no character that can expand, redirect, or start another",
  "  # command, so `eval set --` can only ever run `set`: bash does quote removal and word",
  "  # splitting, and nothing else.",
  "  local s=${c//\\$/$'\\x01'}; s=${s//\\`/$'\\x07'}; s=${s//\\(/$'\\x03'}; s=${s//\\)/$'\\x04'}",
  "  s=${s//</$'\\x02'}; s=${s//>/$'\\x05'}; s=${s//&/$'\\x06'}",
  "  s=${s//|/$'\\x0e'}; s=${s//;/$'\\x0f'}; s=${s//$'\\n'/$'\\x10'}",
  "  if ! eval \"set -- $s\"; then printf '\\x1d\\x01\\x1e'; return 1; fi",
  "  # Rejoin words that bash split inside a neutralised $(...) or `...`: that span is one word.",
  "  local -a words=(); local cur='' depth=0 ticks=0 w t",
  "  for w in \"$@\"; do",
  "    [[ -n $cur ]] && cur+=' '",
  "    cur+=$w",
  "    if [[ -z $__rod_dollar || $cur == *$'\\x01\\x03'* ]]; then t=${w//[^$'\\x03']/}; depth=$((depth + ${#t})); t=${w//[^$'\\x04']/}; depth=$((depth - ${#t})); fi",
  "    t=${w//[^$'\\x07']/}; ticks=$(( (ticks + ${#t}) % 2 ))",
  "    if (( depth <= 0 && ticks == 0 )); then words+=(\"$cur\"); cur=''; depth=0; fi",
  "  done",
  "  if [[ -n $cur ]]; then printf '\\x1d\\x01\\x1e'; return 1; fi",
  "  local out='' skip=0 R=$'[\\x02\\x05\\x06]'",
  "  for w in \"${words[@]}\"; do",
  "    if (( skip )); then skip=0; continue; fi",
  "    # Redirections are in bash's command text but are not words of the command.",
  "    if [[ $w =~ ^[0-9]*$R+-?$ ]]; then skip=1; continue; fi         # operator; its target is the next word",
  "    if [[ $w =~ ^[0-9]*$R+[0-9]+-?$ ]]; then continue; fi           # fd duplication, e.g. 2>&1",
  "    if [[ $w =~ ^[0-9]*$R+ ]]; then continue; fi                     # operator glued to its target",
  "    w=${w//$'\\x01'/\\$}; w=${w//$'\\x07'/\\`}; w=${w//$'\\x03'/(}; w=${w//$'\\x04'/)}",
  "    w=${w//$'\\x02'/<}; w=${w//$'\\x05'/>}; w=${w//$'\\x06'/\"&\"}",
  "    w=${w//$'\\x0e'/|}; w=${w//$'\\x0f'/;}; w=${w//$'\\x10'/$'\\n'}",
  "    out+=$w$'\\x1f'",
  "  done",
  "  [[ -n ${__rod_seen[$out]} ]] && return 1",
  "  __rod_seen[$out]=1",
  "  printf '\\x1d%s\\x1e' \"$out\"",
  "  return 1",
  "}",
  "shopt -s extdebug",
  "set -f -T",
  "eval \"__rod_body() {",
  "$GOL_ROD_SRC",
  "}\" || { printf '\\x1d\\x01\\x1e'; exit 0; }",
  "exec < /dev/null",
  "set -r",
  "trap __rod_trap DEBUG",
  "__rod_body",
].join("\n") + "\n";

// asRun: hand the command over as an argument, the way the Bash tool's bash
// receives it, instead of in the environment. Git Bash halves \\ on its command
// line, so only this route yields the words bash will actually run (measured
// 4 Oct: 9 test strings, byte-identical to the Bash tool; stdin differed on 4).
// asRun also counts parentheses only inside a $( span (__rod_dollar), so a word
// holding a literal unclosed "(" stays readable instead of making the whole
// record unreadable; that is the commonest inline-code SyntaxError. Without
// asRun the lexer is unchanged, and so are the words sent to the server.
// Parts of a command that run at the same time (a pipeline, a job sent off with
// &) report at the same time, and one report can land inside another: node then
// sees code with "sleep 2" in it (11 Oct, 1 run in 30 under load). Every record
// must arrive whole; a split one leaves a stray mark behind. Then bash is asked
// again, and after three tries there is no reading.
function recordsWhole(out) {
  return !/[\x1d\x1e]/.test(String(out || "").replace(/\x1d[^\x1d\x1e]*\x1e/g, ""));
}

// bash -c keeps a lone backslash at the very end of its input as a literal
// character. Inside the rod's wrapper it would instead join the closing } onto
// the command and break it, so the command went unread and unchecked
// (claude-code#5049: move *.md docs\). Doubled, quote removal gives back the
// same single backslash bash itself runs with.
// Safety (thin client, 15 Oct): every bash reader wraps its text in a function
// definition (eval "__b() {<newline><text><newline>}"), which runs nothing only
// if the text cannot close that brace early. A text bash -n accepts on its own
// cannot, so each reader first asks bash -n (which runs nothing) and, if bash
// refuses, reports "unreadable" exactly as a failed eval always did.
const PRE_ENV = (fail) => "\"$BASH\" --noprofile --norc -n -c \"$GOL_ROD_SRC\" >/dev/null 2>&1 || { " + fail + "; }\n";
const PRE_ARG = (fail) => "\"$BASH\" --noprofile --norc -n -c \"$1\" >/dev/null 2>&1 || { " + fail + "; }\n";
const ROD_FAIL = "printf '\\x1d\\x01\\x1e'; exit 0";
const rodSrc = (c) => /(^|[^\\])(\\\\)*\\$/.test(c) ? c + "\\" : c;

function bashWords(command, cwd, asRun = false, dollar = asRun) {
  command = rodSrc(command);
  try {
    const bash = bashPath();
    if (!bash) return null;
    const args = asRun
      ? ["--noprofile", "--norc", "-c", "GOL_ROD_SRC=$1\n" + PRE_ENV(ROD_FAIL) + (dollar ? "__rod_dollar=1\n" : "") + ROD_SH, "check", command]
      : ["--noprofile", "--norc", "-c", PRE_ENV(ROD_FAIL) + (dollar ? "__rod_dollar=1\n" : "") + ROD_SH];
    let r;
    for (let k = 0; k < 3 && !r; k++) {
      r = spawnSync(bash, args, {
        cwd: cwd && existsSync(cwd) ? cwd : undefined,
        env: asRun ? process.env : { ...process.env, GOL_ROD_SRC: command },
        timeout: 3000, encoding: "utf8",
      });
      if (r.error || r.status === null) return null;
      if (!recordsWhole(r.stdout)) r = null;
    }
    if (!r) return null;
    const recs = [];
    let complete = true;
    for (const m of (r.stdout || "").matchAll(/\x1d([^\x1e]*)\x1e/g)) {
      if (m[1] === "\x02") { complete = false; continue; }   // bash stopped walking (loop cap)
      recs.push(m[1] === "\x01" ? null : m[1].split("\x1f").filter(w => w !== ""));
    }
    return { recs, complete };
  } catch { return null; }
}

// PowerShell: command words from one ParseInput call, and each parser's raw
// answer as a fact (pwsh first, then Windows PowerShell). The server judges.
function psCommand(command) {
  const facts = { ps7: { c: null } };
  const script =
    "$ErrorActionPreference='Stop';" +
    "$src=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:GOL_PS_SRC));" +
    "$e=$null;" +
    "$ast=[System.Management.Automation.Language.Parser]::ParseInput($src,[ref]$null,[ref]$e);" +
    "if($e -and $e.Count -gt 0){ Write-Output $e[0].Message; exit 3 }" +
    "$sb=New-Object Text.StringBuilder;" +
    "foreach($c in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst]},$true)){" +
    "[void]$sb.Append([char]0x1d);" +
    "foreach($el in $c.CommandElements){" +
    "if($el -is [System.Management.Automation.Language.StringConstantExpressionAst]){$t=$el.Value}else{$t=$el.Extent.Text};" +
    "[void]$sb.Append($t).Append([char]0x1f)};" +
    "[void]$sb.Append([char]0x1e)};" +
    "[Console]::Out.Write($sb.ToString())";
  for (const bin of ["pwsh", "powershell"]) {
    try {
      const r = spawnSync(bin, ["-NoProfile", "-NonInteractive", "-Command", script], {
        timeout: 6000, encoding: "utf8",
        env: { ...process.env, GOL_PS_SRC: Buffer.from(command, "utf8").toString("base64") },
      });
      if (r.error || r.status === null) continue;
      facts[bin === "pwsh" ? "ps7" : "ps5"] = { c: r.status, m: r.status === 3 ? redact(String(r.stdout || "")).slice(0, 600) : "" };
      if (r.status === 0) {
        const recs = [...(r.stdout || "").matchAll(/\x1d([^\x1e]*)\x1e/g)].map(m => m[1].split("\x1f").filter(w => w !== ""));
        return { facts, lex: { recs, complete: true } };
      }
      if (r.status !== 3) continue;
      return { facts, lex: null };
    } catch { continue; }
  }
  return { facts, lex: null };
}

// --- WORDS THE FIRST WALK DOES NOT REACH (4.3.5) ---------------------------
//
// The rod walks a command with every simple command skipped, and bash reports a
// skipped command as a success. So it walks one side of each branch only: the
// right of `a || b`, an `else` and an `until` body are never reached, and
// neither is anything inside $(...) or `...` (the rod never expands). Three
// more readings, each from this machine's bash, each silent when it cannot read:
//
//   otherBranchWords  bash prints the program back in its own canonical form
//                     (declare -f); `||` becomes `;` and each `if`/`until`
//                     condition is negated, and the rod walks that.
//   substitutionWords bash's own quote removal says which $( and ` are live
//                     (a marker whose backslash pair survives sat in single
//                     quotes); the text inside each live one is walked by the
//                     rod, ending at the first `)` where it reads as complete.
//   shellCWords       the code handed to `bash -c` / `sh -c` is walked too.
//
// These only add words for the server to ask the machine about. They never
// change the words of the first walk. Measured against the 10 Oct tester run.
const SUBST_SH = [
  "__n=0",
  "__sub() {",
  "  local c=$BASH_COMMAND",
  "  __n=$((__n + 1)); if (( __n > 400 )); then exit 0; fi",
  "  [[ $c == __sub_body ]] && return 0",
  "  case $c in 'for '*|'case '*|'select '*|'[['*|'(('*) return 0 ;; esac",
  // No doubled backslash anywhere in this script: it reaches bash on the
  // command line, where Git Bash halves them (the bug the gate itself names).
  "  local bt=$'\\x60' d='$(' bs=$'\\x5c' m1=$'\\x11\\x5c\\x5c\\x12' m2=$'\\x13\\x5c\\x5c\\x14'",
  "  [[ $c == *\"$d\"* || $c == *\"$bt\"* ]] || return 1",
  "  [[ $c == *\"$bs\\$\"* || $c == *\"$bs$bt\"* || $c == *'<<'* ]] && return 1",
  "  if [[ $c =~ \\$\\{[^}]*[[:space:]] ]]; then return 1; fi",
  "  local s=${c//'$(('/$'\\x15'}",
  "  s=${s//\"$d\"/\"$m1\"}; s=${s//\"$bt\"/\"$m2\"}",
  "  s=${s//\\$/$'\\x01'}; s=${s//\\(/$'\\x03'}; s=${s//\\)/$'\\x04'}",
  "  s=${s//</$'\\x02'}; s=${s//>/$'\\x05'}; s=${s//&/$'\\x06'}",
  "  s=${s//|/$'\\x0e'}; s=${s//;/$'\\x0f'}; s=${s//$'\\n'/$'\\x10'}",
  "  eval \"set -- $s\" || return 1",
  "  local all=\"$*\" bits='' i ch nx",
  "  for (( i = 0; i < ${#all}; i++ )); do",
  "    ch=${all:i:1}",
  "    if [[ $ch == $'\\x11' || $ch == $'\\x13' ]]; then",
  "      nx=${all:i+1:2}",
  "      if [[ $nx == \"$bs\"$'\\x12' || $nx == \"$bs\"$'\\x14' ]]; then bits+=1; else bits+=0; fi",
  "    fi",
  "  done",
  "  printf '\\x1d%s\\x1f%s\\x1e' \"$c\" \"$bits\"",
  "  return 1",
  "}",
  "shopt -s extdebug",
  "set -f -T",
  "eval \"__sub_body() {\n$GOL_ROD_SRC\n}\" || exit 0",
  "exec < /dev/null",
  "set -r",
  "trap __sub DEBUG",
  "__sub_body",
].join("\n");
const CANON_SH = "eval \"__b() {\n$GOL_ROD_SRC\n}\" || exit 3\ndeclare -f __b";

function bashScript(script, command, cwd) {
  command = rodSrc(command);
  const bash = bashPath();
  if (!bash) return null;
  try {
    const r = spawnSync(bash, ["--noprofile", "--norc", "-c", PRE_ENV(script === CANON_SH ? "exit 3" : "exit 0") + script], {
      cwd: cwd && existsSync(cwd) ? cwd : undefined,
      env: { ...process.env, GOL_ROD_SRC: command }, timeout: 3000, encoding: "utf8",
    });
    return r.error || r.status === null ? null : r;
  } catch { return null; }
}

// --- FACTS AND PARSERS (4.3.5): the client gathers, the server decides ------
//
// This client holds no rule about what is wrong. It reports its shell's
// readings of a command, and when the server asks, it runs one named parser on
// one referenced text and returns the exit code and output. Which questions to
// ask, when to stay silent and what an answer means are the server's.
//
// Parsers: bash (-n), ps7 / ps5 (ParseInput), py (compile), npmjson
// (JSON.parse after a BOM, as npm reads package.json), node:.mjs / node:.cjs
// (node --check on a temp copy), inode-script / inode-module / ipy (the code of
// node -e or python -c, with the interpreter bash would run).
// Sources: the command, a word of a reading, the written file after / before,
// lines of bash's printed form of the command, a file at a shell path.
//
// Two limits that are the client's own, for the user's safety: an interpreter
// is only ever node or python, and only py-launcher version selectors pass as
// flags. Output is cut to the error lines and redacted before it leaves.

const NODE_SCRIPT_PARSE = "let s='';process.stdin.setEncoding('utf8');process.stdin.on('data',d=>s+=d).on('end',()=>{try{new (require('vm').Script)(s,{filename:'[eval]'})}catch(e){if(e instanceof SyntaxError){process.stderr.write(e.message);process.exit(3)}process.exit(4)}process.exit(0)})";
const PY_PARSE = "import sys\ntry:\n compile(sys.stdin.buffer.read().decode('utf-8'), '<string>', 'exec')\nexcept SyntaxError as e:\n sys.stderr.write('%s (line %s)' % (e.msg, e.lineno)); sys.exit(3)";
const PY_FILE_PARSE = "import sys;\ntry:\n compile(sys.stdin.read(), '<check>', 'exec')\nexcept SyntaxError as e:\n sys.stderr.write('%s (line %s)' % (e.msg, e.lineno)); sys.exit(3)";
const PS_PARSE =
  "$ErrorActionPreference='Stop';" +
  "$src=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:GOL_PS_SRC));" +
  "$e=$null;" +
  "[void][System.Management.Automation.Language.Parser]::ParseInput($src,[ref]$null,[ref]$e);" +
  "if($e -and $e.Count -gt 0){ Write-Output $e[0].Message; exit 3 }";
const PARSE_MAX = 2_000_000;

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=/;

// The interpreter bash itself would run, as a path node can start directly.
function interpreterPath(word, cwd) {
  const bash = bashPath();
  if (!bash) return null;
  const script = platform() === "win32" ? 'p=$(type -P -- "$1") && cygpath -w -- "$p"' : 'type -P -- "$1"';
  try {
    const r = spawnSync(bash, ["--noprofile", "--norc", "-c", script, "check", word], {
      cwd: cwd && existsSync(cwd) ? cwd : undefined, timeout: 3000, encoding: "utf8",
    });
    const out = (r.stdout || "").trim();
    return r.status === 0 && out ? out : null;
  } catch { return null; }
}

// Parser output, cut to what names the error. node prints the offending source
// line of the file; that line stays here. Then the same redaction as commands.
// node: its location line ("file.mjs:3", "[stdin]:3") and its "XError: msg"
// line, never the source line between them. bash: "...: line N: ..." lines and
// its here-document warning.
function errorText(s, n, kind) {
  const keep = kind === "bash"
    ? (l) => /:\s*line \d+:|warning: here-document/.test(l)
    : (l) => /^(\S*file\.[a-z]+:\d+|\[stdin\]:\d+|\[eval\]:\d+)\s*$/.test(l.trim()) || /^\w*Error: /.test(l.trim());
  return redact(String(s || "").split("\n").filter(keep).join("\n")).slice(0, n);
}

const idOf = (p, s, x, f = []) => JSON.stringify([p, s, x || "", f]);

function runParser(p, text, x, flags, cwd) {
  if (typeof text !== "string" || text.length > PARSE_MAX) return { c: null };
  const opts = { input: text, timeout: 6000, encoding: "utf8", maxBuffer: 1 << 24 };
  try {
    if (p === "bash") {
      const b = bashPath();
      if (!b) return { c: null };
      const r = spawnSync(b, ["-n"], opts);
      return r.error ? { c: null } : { c: r.status, m: errorText(r.stderr, 1000, "bash") };
    }
    if (p === "ps7" || p === "ps5") {
      const r = spawnSync(p === "ps7" ? "pwsh" : "powershell", ["-NoProfile", "-NonInteractive", "-Command", PS_PARSE], {
        timeout: 6000, encoding: "utf8", env: { ...process.env, GOL_PS_SRC: Buffer.from(text, "utf8").toString("base64") },
      });
      return r.error || r.status === null ? { c: null } : { c: r.status, m: redact(String(r.stdout || "")).slice(0, 600) };
    }
    if (p === "py") {
      for (const bin of ["python3", "python", "py"]) {
        const r = spawnSync(bin, ["-c", PY_FILE_PARSE], opts);
        if (r.error) continue;
        if (r.status === 0 || r.status === 3) return { c: r.status, m: redact(String(r.stderr || "")).slice(0, 600) };
      }
      return { c: null };
    }
    if (p === "npmjson") {
      try { JSON.parse(text.replace(/^\uFEFF/, "")); return { c: 0 }; }
      catch (e) { return { c: 1, m: redact(String(e.message || e)).slice(0, 300) }; }
    }
    if (p === "node:.mjs" || p === "node:.cjs") {
      let dir;
      try {
        dir = mkdtempSync(join(tmpdir(), "check-js-"));
        const f = join(dir, "file" + p.slice(5));
        writeFileSync(f, text);
        const r = spawnSync(process.execPath, ["--check", f], { timeout: 5000, encoding: "utf8" });
        return r.error || r.status === null ? { c: null } : { c: r.status, m: errorText(r.stderr, 1000, "node") };
      } finally { if (dir) try { rmSync(dir, { recursive: true, force: true }); } catch {} }
    }
    if (p === "inode-script" || p === "inode-module" || p === "ipy") {
      const kind = String(x || "").replace(/^.*[\\/]/, "").toLowerCase().replace(/\.exe$/, "");
      const isNode = kind === "node", isPy = ["python", "python3", "py"].includes(kind);
      if ((p === "ipy" && !isPy) || (p !== "ipy" && !isNode)) return { c: null };
      const exe = interpreterPath(x, cwd);
      if (!exe) return { c: null };
      let r;
      if (p === "inode-script") r = spawnSync(exe, ["-e", NODE_SCRIPT_PARSE], opts);
      else if (p === "inode-module") r = spawnSync(exe, ["--input-type=module", "--check"], opts);
      else {
        const sel = (Array.isArray(flags) ? flags : []).filter(f => /^-(\d[\d.-]*|V:[\w.\/-]+)$/.test(f));
        r = spawnSync(exe, [...sel, "-c", PY_PARSE], opts);
      }
      return r.error || r.status === null ? { c: null } : { c: r.status, m: p === "inode-script" || p === "ipy" ? redact(String(r.stderr || "")).slice(0, 600) : errorText(r.stderr, 1000, "node") };
    }
  } catch { return { c: null }; }
  return { c: null };
}

// A path as bash would take it, from where the command runs: ~/x, /c/x, C:\x,
// or relative. Anything else (/tmp, an MSYS root path) has no answer here.
function shellPath(t, cwd) {
  if (typeof t !== "string" || !t) return null;
  if (/^~\//.test(t)) return join(homedir(), t.slice(2));
  if (/^\/[a-zA-Z]\//.test(t)) return t[1] + ":" + t.slice(2);
  if (/^[a-zA-Z]:[\\/]/.test(t)) return t;
  if (t.startsWith("/") || t.startsWith("~")) return null;
  return join(cwd && existsSync(cwd) ? cwd : process.cwd(), t);
}

function sourceText(s, ctx) {
  if (!s || typeof s !== "object") return null;
  try {
    if (s.k === "cmd") return ctx.command ?? null;
    if (s.k === "word") {
      const w = ctx.read?.[s.r]?.[s.i]?.[s.j];
      if (typeof w !== "string") return null;
      return s.eq ? w.slice(w.indexOf("=") + 1) : w;
    }
    if (s.k === "after") return ctx.after ?? null;
    if (s.k === "before") return ctx.path ? readFileSync(ctx.path, "utf8") : null;
    if (s.k === "canon") {
      const L = ctx.canon?.[s.r];
      if (!Array.isArray(L) || !Number.isInteger(s.a)) return null;
      // A span of one line (the text echo or printf writes), as named.
      if (Number.isInteger(s.from) && Number.isInteger(s.to)) {
        if (typeof L[s.a] !== "string") return null;
        let t = L[s.a].slice(s.from, s.to);
        if (s.unesc) t = t.split("\\n").join("\n");
        return s.nl ? t + "\n" : t;
      }
      if (!Number.isInteger(s.b)) return null;
      const body = L.slice(s.a, s.b);
      return body.length ? body.join("\n") + "\n" : "";
    }
    if (s.k === "file") { const p = shellPath(s.p, ctx.cwd); return p ? readFileSync(p, "utf8") : null; }
  } catch { return null; }
  return null;
}

function answerParse(reqs, ctx) {
  const out = {};
  for (const q of (Array.isArray(reqs) ? reqs : []).slice(0, 24)) {
    if (!q || typeof q.id !== "string") continue;
    if (q.p === "exists") {
      const p = q.s?.k === "file" ? shellPath(q.s.p, ctx.cwd) : null;
      out[q.id] = { c: 0, e: p === null ? null : existsSync(p) ? 1 : 0 };
      continue;
    }
    out[q.id] = runParser(q.p, sourceText(q.s, ctx), q.x, q.f, ctx.cwd);
  }
  return out;
}

// bash's printed form of a command (declare -f): the heredoc bodies it would
// write, by both routes (as typed, and through Git Bash's command line).
const CANON_ARG_SH = PRE_ARG("exit 3") + "eval \"__b() {\n$1\n}\" || exit 3\ndeclare -f __b";
const CANON_ENV_SH = PRE_ENV("exit 3") + "eval \"__b() {\n$GOL_ROD_SRC\n}\" || exit 3\ndeclare -f __b";
function canonLines(command, cwd, asRun) {
  command = rodSrc(command);
  const bash = bashPath();
  if (!bash) return null;
  try {
    const r = spawnSync(bash, ["--noprofile", "--norc", "-c", ...(asRun ? [CANON_ARG_SH, "check", command] : [CANON_ENV_SH])], {
      cwd: cwd && existsSync(cwd) ? cwd : undefined, timeout: 3000, encoding: "utf8",
      env: asRun ? process.env : { ...process.env, GOL_ROD_SRC: command },
    });
    if (r.error || r.status !== 0) return null;
    return (r.stdout || "").replace(/\r/g, "").split("\n");
  } catch { return null; }
}

// The npm packages a JavaScript or TypeScript write starts importing that this
// project neither has installed nor declares (4.3.6). Only their names go to
// the server, never the code. Nothing at all where an import name may not be a
// package: path aliases (tsconfig/jsconfig paths or baseUrl, a bundler alias),
// workspaces, package "imports", import maps, Deno.
const JS_EXT = /\.(?:[cm]?[jt]sx?)$/i;
function importNames(src) {
  if (typeof src !== "string" || src.length > 1_000_000) return new Set();
  const code = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:\\])\/\/[^\n]*/g, "$1");
  const names = new Set();
  const take = (spec) => {
    if (!spec || /^[./~#@]\/|^[./#~]|^(?:node|bun|npm|jsr|https?|file|data|virtual):/i.test(spec) || spec.startsWith("@/")) return;
    const parts = spec.split("/");
    const name = spec.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
    if (/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(name)) names.add(name);
  };
  // import 'x'; import ... from 'x'; export ... from 'x'. A statement only:
  // `from` is required except in the bare side-effect form.
  for (const m of code.matchAll(/^[ \t]*import\s*(['"])([^'"\n]+)\1/gm)) take(m[2]);
  for (const m of code.matchAll(/^[ \t]*(?:import|export)\b[^'"`;]*?\bfrom\s*(['"])([^'"\n]+)\1/gm)) take(m[2]);
  for (const m of code.matchAll(/(?:^|[=(,;:!&|?{}\s])(?:require|import)\s*\(\s*(['"])([^'"\n]+)\1\s*\)/gm)) take(m[2]);
  return names;
}
// The names a write starts importing, and the facts of each folder from the
// file's up to the home folder: package.json (its declared names, workspaces),
// path aliases, Deno, bundler aliases, monorepo files, .git, node_modules.
// Which of them silence the check, and where the walk stops: the server's.
async function importScan(path, after) {
  try {
    if (!JS_EXT.test(path) || typeof after !== "string") return null;
    let before = "";
    try { before = existsSync(path) ? readFileSync(path, "utf8") : ""; } catch { return null; }
    const had = importNames(before);
    const added = [...importNames(after)].filter(n => !had.has(n)).slice(0, 20);
    if (!added.length) return { added: [], builtin: [], dirs: [] };
    const { builtinModules } = await import("node:module");
    const builtins = new Set(builtinModules);
    const home = (() => { try { return homedir().toLowerCase(); } catch { return ""; } })();
    const dirs = [];
    let dir = dirname(path);
    for (let i = 0; i < 40 && dir; i++) {
      if (dir.toLowerCase() === home) break;
      const d = { git: existsSync(join(dir, ".git")) };
      for (const f of ["tsconfig.json", "jsconfig.json"]) {
        const t = existsSync(join(dir, f)) ? readFileSync(join(dir, f), "utf8") : "";
        if (/"(?:paths|baseUrl)"\s*:/.test(t)) d.paths = true;
      }
      if (["deno.json", "deno.jsonc", "import_map.json"].some(f => existsSync(join(dir, f)))) d.deno = true;
      let listing = [];
      try { listing = readdirSync(dir); } catch {}
      for (const f of listing) {
        if (/^(?:vite|webpack|rollup|next|nuxt|svelte|astro|babel|metro|craco|vue)\.config\.[cm]?[jt]s$|^\.babelrc/i.test(f)) {
          try { if (/alias/i.test(readFileSync(join(dir, f), "utf8"))) d.alias = true; } catch { d.alias = true; }
        }
      }
      const pj = join(dir, "package.json");
      if (existsSync(pj)) {
        d.pkg = true;
        let j = null; try { j = JSON.parse(readFileSync(pj, "utf8").replace(/^\uFEFF/, "")); } catch { d.pkgBad = true; }
        if (j) {
          if (j.workspaces || j.imports) d.ws = true;
          const declared = new Set(typeof j.name === "string" ? [j.name] : []);
          for (const k of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) for (const n of Object.keys(j[k] || {})) declared.add(n);
          d.decl = added.map(n => declared.has(n));
        }
      }
      d.inst = added.map(n => existsSync(join(dir, "node_modules", n)));
      if (existsSync(join(dir, "pnpm-workspace.yaml")) || existsSync(join(dir, "lerna.json"))) d.mono = true;
      dirs.push(d);
      const up = dirname(dir);
      if (up === dir) break;
      dir = up;
    }
    return { added, builtin: added.map(n => builtins.has(n)), dirs };
  } catch { return null; }
}

const redactRecs = (recs) => Array.isArray(recs) ? recs.slice(0, 300).map(r => Array.isArray(r) ? r.slice(0, 64).map(w => redact(w)) : null) : null;

// PowerShell's own answer (15 Oct): which names are a cmdlet is asked of
// PowerShell (Get-Alias, kept a day); what each parameter receives is asked of
// its parameter binder. Each call of the cmdlet in the command is made on a
// stand-in built from the real cmdlet's own parameter block, which only prints
// what was bound. Nothing else in the command runs; a call with a variable, a
// subexpression or a splat is not made at all (no fact for the command).
function psNames(cmdlet) {
  const file = join(homedir(), ".check", "ps-names-" + cmdlet.toLowerCase() + ".json");
  try {
    const s = statSync(file);
    if (Date.now() - s.mtimeMs < 86400000) return new Set(JSON.parse(readFileSync(file, "utf8")));
  } catch {}
  try {
    const r = spawnSync("powershell", ["-NoProfile", "-NonInteractive", "-Command", "(Get-Alias -Definition " + cmdlet + ").Name -join \"`n\""], { timeout: 6000, encoding: "utf8", windowsHide: true });
    if (r.error || r.status !== 0) return null;
    const names = [cmdlet.toLowerCase(), ...String(r.stdout || "").split(/\r?\n/).map(s => s.trim().toLowerCase()).filter(Boolean)];
    try { mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, JSON.stringify(names)); } catch {}
    return new Set(names);
  } catch { return null; }
}
const PS_BIND = [
  "$e = $null; $ast = [System.Management.Automation.Language.Parser]::ParseInput($env:GOL_PS_SRC, [ref]$null, [ref]$e)",
  "if ($e.Count) { exit 3 }",
  "$want = $env:GOL_PS_CMDLET",
  "$md = [System.Management.Automation.CommandMetadata]::new((Get-Command $want -CommandType Cmdlet))",
  "$pb = [System.Management.Automation.ProxyCommand]::GetParamBlock($md)",
  "$cb = [System.Management.Automation.ProxyCommand]::GetCmdletBindingAttribute($md)",
  "$def = \"function __GolBound { $cb param($pb) 'CALL'; foreach (`$k in `$PSBoundParameters.Keys) { foreach (`$v in @(`$PSBoundParameters[`$k])) { 'ARG[' + `$k + '=' + `$v + ']' } } }\"",
  ". ([scriptblock]::Create($def))",
  "foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {",
  "  $n = $c.GetCommandName(); if (-not $n) { continue }",
  "  $ci = Get-Command $n -ErrorAction SilentlyContinue | Select-Object -First 1; if (-not $ci) { continue }",
  "  if ($ci.CommandType -eq 'Alias') { $ci = $ci.ResolvedCommand }",
  "  if ($ci.Name -ne $want) { continue }",
  "  $t = $c.Extent.Text; $h = $c.CommandElements[0].Extent",
  "  $rest = $t.Substring($h.EndOffset - $c.Extent.StartOffset)",
  "  if ($rest -match '[$@(){}`;|&]') { 'SKIP'; continue }",
  "  try { & ([scriptblock]::Create('__GolBound' + $rest)) } catch { 'SKIP' }",
  "}",
].join("\n");
// Each call: { name: [values] }, as the binder bound them; null: no answer.
function psBound(command, cwd, cmdlet) {
  try {
    const r = spawnSync("powershell", ["-NoProfile", "-NonInteractive", "-Command", PS_BIND], { cwd: cwd && existsSync(cwd) ? cwd : undefined, env: { ...process.env, GOL_PS_SRC: command, GOL_PS_CMDLET: cmdlet }, timeout: 6000, encoding: "utf8", windowsHide: true });
    if (r.error || r.status !== 0) return null;
    const lines = String(r.stdout || "").split(/\r?\n/);
    if (lines.some(l => l.trim() === "SKIP")) return null;
    const calls = [];
    for (const l of lines) {
      if (l.trim() === "CALL") { calls.push({}); continue; }
      const m = l.match(/^ARG\[([A-Za-z]+)=(.*)\]$/);
      if (m && calls.length) (calls[calls.length - 1][m[1].toLowerCase()] ||= []).push(m[2]);
    }
    return calls;
  } catch { return null; }
}
// --- DOCKER IMAGES THIS MACHINE DOESN'T HAVE (15 Oct) ------------------------
function bashToWin(paths, cwd) {
  if (platform() !== "win32") return paths;
  const bash = bashPath();
  const conv = bash ? [join(dirname(bash), "cygpath.exe"), join(dirname(bash), "..", "usr", "bin", "cygpath.exe")].find(f => existsSync(f)) : null;
  if (!conv) return null;
  try {
    const r = spawnSync(conv, ["-w", "-a", "--", ...paths], { cwd: cwd && existsSync(cwd) ? cwd : undefined, encoding: "utf8", timeout: 3000, windowsHide: true });
    const lines = String(r.stdout || "").split(/\r?\n/).filter(Boolean);
    return r.status === 0 && lines.length === paths.length ? lines : null;
  } catch { return null; }
}

// --- COPIES THAT CANNOT FIT (13 Oct) -----------------------------------------
// The fact: how many bytes a recursive copy would write and how much space the
// destination has (opencode#54292: "2.0M" stated, ~2 GB copied, disk full, an
// 11-hour build lost). Measured by walking the sources (stopping as soon as
// they exceed the free space, or after COPY_WALK_MS: then no fact) and asking
// the file system for the destination's free space. A destination folder that
// already holds files is skipped: an overwrite may need less. The server decides.
const COPY_WALK_MS = 1500;
function treeBytes(p, limit, deadline) {
  let total = 0;
  const stack = [p];
  while (stack.length) {
    if (Date.now() > deadline) return null;
    const cur = stack.pop();
    let st; try { st = lstatSync(cur); } catch { continue; }
    if (st.isDirectory()) { try { for (const n of readdirSync(cur)) stack.push(join(cur, n)); } catch {} }
    else if (st.isFile()) { total += st.size; if (total > limit) return { bytes: total, over: true }; }
  }
  return { bytes: total, over: false };
}
// --- INVENTED LIBRARY NAMES (4.3.7) -------------------------------------------
//
// A TypeScript write that uses a name a library's own type definitions don't
// have (an export, a method, an option) won't compile. The project's own
// TypeScript (5 or 6; 7 has no programming interface) is run in memory with the
// new content: no file is written. It reports each error inside the edited
// region by its code and line; the server says which matter and asks for the
// details of those (the name, the library, TypeScript's one-line message).
// Never the code. Capped: past TS_CAP_MS the write goes ahead and the cache
// warms in the background.
const TS_CHECK = String.raw`import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const say = (o) => { process.stdout.write(JSON.stringify(o)); };
try {
  const file = path.resolve(input.file);
  let dir = path.dirname(file), cfgPath = null;
  for (let i = 0; i < 40; i++) {
    if (fs.existsSync(path.join(dir, 'tsconfig.json'))) { cfgPath = path.join(dir, 'tsconfig.json'); break; }
    const up = path.dirname(dir); if (up === dir) break; dir = up;
  }
  if (!cfgPath) { say({ ok: false, why: 'no tsconfig' }); process.exit(0); }
  const req = createRequire(path.join(path.dirname(cfgPath), 'noop.js'));
  let ts;
  try { ts = req('typescript'); } catch { say({ ok: false, why: 'no typescript' }); process.exit(0); }

  const parsed = ts.getParsedCommandLineOfConfigFile(cfgPath, {}, { ...ts.sys, onUnRecoverableConfigFileDiagnostic: () => {} });
  if (!parsed) { say({ ok: false, why: 'bad tsconfig' }); process.exit(0); }
  const norm = (p) => path.resolve(p).toLowerCase();
  const inProject = parsed.fileNames.some(f => norm(f) === norm(file));
  const roots = inProject ? parsed.fileNames : [...parsed.fileNames, file];
  fs.mkdirSync(input.cacheDir, { recursive: true });
  const key = crypto.createHash('sha256').update(norm(cfgPath)).digest('hex').slice(0, 16);
  const options = { ...parsed.options, noEmit: true, incremental: true, tsBuildInfoFile: path.join(input.cacheDir, key + '.tsbuildinfo') };
  const host = ts.createIncrementalCompilerHost(options);
  const readFile = host.readFile.bind(host), exists = host.fileExists.bind(host);
  host.readFile = (f) => norm(f) === norm(file) ? input.after : readFile(f);
  host.fileExists = (f) => norm(f) === norm(file) ? true : exists(f);
  const getSF = host.getSourceFile.bind(host);
  host.getSourceFile = (f, lang, onErr, shouldCreate) => {
    if (norm(f) !== norm(file)) return getSF(f, lang, onErr, shouldCreate);
    const s = ts.createSourceFile(f, input.after, lang, true);
    s.version = crypto.createHash('sha256').update(input.after).digest('hex');
    return s;
  };
  const builder = ts.createIncrementalProgram({ rootNames: roots, options, host });
  const program = builder.getProgram();
  const checker = program.getTypeChecker();
  const sf = program.getSourceFiles().find(s => norm(s.fileName) === norm(file));
  if (!sf) { say({ ok: false, why: 'file not in program' }); process.exit(0); }
  const diags = builder.getSemanticDiagnostics(sf);
  try { builder.emitBuildInfo?.(); } catch {}
  try { program.emitBuildInfo?.(); } catch {}

  const libOf = (decl) => {
    const fn = decl?.getSourceFile?.().fileName || '';
    const m = fn.replace(/\\/g, '/').match(/\/node_modules\/((?:@[^/]+\/)?[^/]+)\//);
    if (!m) return null;
    return m[1] === '@types' ? null : m[1].replace(/^@types\//, '');
  };
  const typesLib = (decl) => {
    const fn = (decl?.getSourceFile?.().fileName || '').replace(/\\/g, '/');
    const m = fn.match(/\/node_modules\/@types\/([^/]+)\//);
    if (!m) return libOf(decl);
    return m[1].includes('__') ? '@' + m[1].replace('__', '/') : m[1];
  };
  const nodeAt = (pos) => {
    let found = null;
    const visit = (n) => { if (pos >= n.getStart(sf) && pos < n.getEnd()) { found = n; ts.forEachChild(n, visit); } };
    visit(sf);
    return found;
  };
  // Every error inside the edit, with what TypeScript says about the spot:
  // the property access, the import, or the object literal it sits in, and the
  // libraries their declarations come from. Which errors matter: the server's.
  const libsOf = (t) => { const sym = t?.getSymbol() || t?.aliasSymbol; return (sym?.getDeclarations?.() || []).map(typesLib); };
  const out = [];
  for (const d of diags) {
    if (d.start === undefined || d.start < input.from || d.start >= input.to) continue;
    const n = nodeAt(d.start);
    const det = { msg: ts.flattenDiagnosticMessageText(d.messageText, ' ').slice(0, 300) };
    let pa = n;
    while (pa && !ts.isPropertyAccessExpression(pa)) pa = pa.parent;
    if (pa) det.access = { name: pa.name.text, libs: libsOf(checker.getTypeAtLocation(pa.expression)) };
    let imp = n;
    while (imp && !ts.isImportDeclaration(imp)) imp = imp.parent;
    if (imp && ts.isStringLiteral(imp.moduleSpecifier)) {
      const decl = checker.getSymbolAtLocation(imp.moduleSpecifier)?.getDeclarations?.()?.[0];
      det.import = { lib: typesLib(decl) };
    }
    let prop = n;
    while (prop && !ts.isPropertyAssignment(prop) && !ts.isShorthandPropertyAssignment(prop)) prop = prop.parent;
    const obj = prop?.parent;
    if (obj && ts.isObjectLiteralExpression(obj)) {
      const t0 = checker.getContextualType(obj);
      det.prop = { name: prop.name?.getText?.(sf) || null, libs: libsOf(t0 ? checker.getNonNullableType(t0) : t0) };
    }
    out.push({ code: d.code, line: sf.getLineAndCharacterOfPosition(d.start).line + 1, det });
    if (out.length >= 20) break;
  }
  say({ ok: true, diags: out });
} catch (e) {
  say({ ok: false, why: String(e && e.message || e).slice(0, 200) });
}
`;
const TS_CAP_MS = 2500;
const TS_EXT = /\.(?:[cm]?tsx?)$/i;
function editedRegion(before, after) {
  if (typeof before !== "string") return [0, after.length];
  let a = 0;
  while (a < before.length && a < after.length && before[a] === after[a]) a++;
  let b = 0;
  while (b < before.length - a && b < after.length - a && before[before.length - 1 - b] === after[after.length - 1 - b]) b++;
  return [a, Math.max(a, after.length - b)];
}
function tsFacts(path, after) {
  try {
    if (!TS_EXT.test(path) || /\.d\.ts$/i.test(path) || typeof after !== "string" || after.length > 500000) return null;
    let before = null;
    try { before = existsSync(path) ? readFileSync(path, "utf8") : null; } catch {}
    const [from, to] = editedRegion(before, after);
    if (to <= from) return null;
    const input = JSON.stringify({ file: path, after, from, to, cacheDir: join(homedir(), ".check", "tscache") });
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", TS_CHECK], { input, encoding: "utf8", timeout: TS_CAP_MS, windowsHide: true });
    if (r.error || r.status === null) {
      // Too slow this time: let it finish in the background so the next write is warm.
      try {
        const c = spawn(process.execPath, ["--input-type=module", "-e", TS_CHECK], { detached: true, stdio: ["pipe", "ignore", "ignore"], windowsHide: true });
        c.stdin.end(input); c.unref();
      } catch {}
      return null;
    }
    const o = JSON.parse(r.stdout || "null");
    return o && o.ok && Array.isArray(o.diags) ? o.diags.slice(0, 20) : null;
  } catch { return null; }
}

// npm run <name>: npm looks for the script in the package.json of the nearest
// folder, walking up, that has a package.json or node_modules. Read here, in
// JavaScript, the way npm reads it. null = no answer.
function npmScriptAnswer(name, cwd) {
  let dir = cwd && existsSync(cwd) ? cwd : process.cwd();
  for (let i = 0; i < 60 && dir; i++) {
    const pj = join(dir, "package.json");
    if (existsSync(pj)) {
      try {
        const s = JSON.parse(readFileSync(pj, "utf8").replace(/^﻿/, "")).scripts;
        return !!(s && typeof s === "object" && Object.prototype.hasOwnProperty.call(s, name));
      } catch { return null; }
    }
    if (existsSync(join(dir, "node_modules"))) return false;
    const up = dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return null;
}

// The file's post-edit content, computed the same way the tool would compute
// it. String.prototype.replace treats $-prefixed sequences as patterns; use
// split/join for a literal replacement so the parser judges what actually
// gets written.
function contentAfter(p) {
  const ti = p.tool_input || {};
  const path = ti.file_path || ti.filePath || ti.path;
  if (!path) return null;
  if (typeof ti.content === "string") return { path, content: ti.content };
  if (typeof ti.new_string === "string" && typeof ti.old_string === "string") {
    let current;
    try { current = readFileSync(path, "utf8"); } catch { return null; }
    if (ti.old_string === "") return null;
    if (!current.includes(ti.old_string)) return null;
    const parts = current.split(ti.old_string);
    const next = ti.replace_all
      ? parts.join(ti.new_string)
      : parts[0] + ti.new_string + parts.slice(1).join(ti.old_string);
    return { path, content: next };
  }
  return null;
}

// --- RECEIPT ---------------------------------------------------------------
//
// Per message, count what Check did: c = checked, b = blocked, u = not checked
// (Check itself could not answer, and let it run). One append-only file per
// message so parallel tool calls never overwrite each other. Local only:
// nothing here is ever sent anywhere.
let CURRENT_PROMPT = null;
const RECEIPTS = join(homedir(), ".check", "receipts");
const safeId = (id) => String(id || "").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 80);
function tally(kind, reason) {
  const id = safeId(CURRENT_PROMPT);
  if (!id) return;
  try {
    mkdirSync(RECEIPTS, { recursive: true });
    const short = reason ? " " + String(reason).replace(/^check:\s*/, "").replace(/\s+/g, " ").slice(0, 90) : "";
    appendFileSync(join(RECEIPTS, id), kind + short + "\n");
  } catch {}
}
function receiptFor(promptId) {
  const id = safeId(promptId);
  if (!id) return null;
  const file = join(RECEIPTS, id);
  let lines = [];
  try { lines = readFileSync(file, "utf8").split("\n").filter(Boolean); } catch { return null; }
  try { unlinkSync(file); } catch {}
  // Tidy receipts left by responses that never finished (older than two days).
  try { for (const n of readdirSync(RECEIPTS)) { const p = join(RECEIPTS, n); if (Date.now() - statSync(p).mtimeMs > 2 * 86400000) unlinkSync(p); } } catch {}
  const checked = lines.filter(l => l[0] === "c" || l[0] === "b").length;
  const blocked = lines.filter(l => l[0] === "b");
  const unchecked = lines.filter(l => l[0] === "u").length;
  if (!checked && !unchecked) return null;
  let msg = "Check: " + checked + " action" + (checked === 1 ? "" : "s") + " checked";
  if (blocked.length) msg += ", " + blocked.length + " blocked (" + blocked[0].slice(2) + (blocked.length > 1 ? "; +" + (blocked.length - 1) + " more" : "") + ")";
  if (unchecked) msg += ", " + unchecked + " not checked";
  return msg;
}

// --- HOOK OUTPUT SHAPES ----------------------------------------------------
//
// Hook verdicts never call process.exit(): after a second server round the
// loop still holds undici keep-alive teardown, and a forced exit trips a
// libuv assertion on Windows (async.c:76). Set exitCode and let the loop
// drain. A deny that exits dirty is not a deny.

// The verdict, in the asking tool's own words: the server's format table
// (replies) says how each tool expects go ahead, stop, a notice, and the
// answer to a message. `silent`: an event Check doesn't judge, answered "go
// ahead" and not counted in the receipt.
function fill(x, vars) {
  if (typeof x === "string") return x === "$reason" ? vars.reason || "" : x === "$notice" ? vars.notice || "" : x;
  if (Array.isArray(x)) return x.map(y => fill(y, vars));
  if (x && typeof x === "object") { const o = {}; for (const [k, v] of Object.entries(x)) o[k] = fill(v, vars); return o; }
  return x;
}
function say(f, which, vars = {}) {
  const R = REPLIES || {};
  const r = fill(R[which] || {}, vars);
  process.exitCode = typeof r.exit === "number" ? r.exit : 0;
  if (r.stdout !== undefined) process.stdout.write(JSON.stringify(r.stdout));
  if (typeof r.stderr === "string" && r.stderr) process.stderr.write(r.stderr);
}
function out(f, ok, reason, silent = false) {
  if (!silent) tally(ok ? "c" : "b", ok ? "" : reason);
  say(f, ok ? "allow" : "deny", { reason });
}

// One-voice fail-open messages. `check:` prefix, what's paused, what still
// runs, one line on the fix.
const NOTICE = {
  rate_limit:      'check: rate limited. Verification paused; local syntax check still runs. Waits out in a minute.',
  server_error:    (n) => 'check: verification service is down (HTTP ' + n + '). Local syntax check still runs. Resumes automatically.',
  credits:         () => 'check: no credit left (your free trial has ended or your balance is empty), so Check is not checking. Nothing is blocked. Top up at golproductions.com/console.',
  key_rejected:    'check: this key was not accepted. Local syntax check still runs. Fix or replace at golproductions.com/console.',
  unreachable:     'check: verification service unreachable, command ran unverified. Resumes automatically.',
  bad_input:       'check: hook input could not be read, so this command ran unverified. Nothing is blocked.',
  no_key:          'check: no GOL API Key on this machine, so commands run unverified. Nothing is blocked. The person at this computer: get a key at golproductions.com/console, then add it in the settings of your Check plugin, or with the Check installer (golproductions.com/guide).',
};

// Billing / traffic state: warn once per day per category, then let the
// command run ungated. Category-keyed marker so a bad-key warning this
// morning doesn't silently swallow a balance warning this afternoon.
function outCreditsExhausted(f, reason, category = "general") {
  tally("u");
  let warned = true;
  try {
    const safeCategory = String(category).replace(/[^a-z0-9_-]/gi, "_").slice(0, 40);
    const marker = join(homedir(), ".check", `credits-warned-${safeCategory}-` + new Date().toISOString().slice(0, 10));
    warned = existsSync(marker);
    if (!warned) { mkdirSync(join(homedir(), ".check"), { recursive: true }); writeFileSync(marker, "1"); }
  } catch { warned = false; }
  const msg = warned ? undefined : reason;
  say(f, msg ? "notice" : "allow", { notice: msg });
}


// --- PROBE PROTOCOL --------------------------------------------------------
//
// The server names any fact it cannot resolve (a word, a "path:", a "gitcmd:"/
// "gitref:") and this client answers with the machine's own verdict. Turns
// list-faith into ground truth.

const PROBE_SH = `for k in "$@"; do
  r=0; w=""
  case "$k" in
    path:*) p="\${k#path:}"; [ -e "$p" ] && r=1 ;;
    gitcmd:*) s="\${k#gitcmd:}"
      if git --list-cmds=main,others,alias,parse-opt 2>/dev/null | grep -Fxq -- "$s"; then r=1
      elif type -- "git-$s" >/dev/null 2>&1; then r=1; fi ;;
    gitref:*) f="\${k#gitref:}"
      if git rev-parse --verify --quiet "$f" >/dev/null 2>&1; then r=1
      elif git ls-files --error-unmatch -- "$f" >/dev/null 2>&1; then r=1
      elif [ -n "$(git for-each-ref --count=1 --format=x "refs/remotes/*/$f" 2>/dev/null)" ]; then r=1; fi ;;
    cddir:*) t="\${k#cddir:}"; ( cd -- "$t" ) >/dev/null 2>&1 && r=1 ;;
    gitremote:*) t="\${k#gitremote:}"; { git remote 2>/dev/null | grep -Fxq -- "$t" || [ -e "$t" ]; } && r=1 ;;
    script:*) t="\${k#script:}"; kind="\${t%%:*}"; f="\${t#*:}"
      case "$kind" in
        node) for x in "" .js .mjs .cjs .json .node .ts .mts .cts; do [ -e "$f$x" ] && { r=1; break; }; done ;;
        sh) { [ -e "$f" ] || type -P -- "$f" >/dev/null 2>&1; } && r=1 ;;
        *) [ -e "$f" ] && r=1 ;;
      esac ;;
    npxbin:*) b="\${k#npxbin:}"; n="\${b##*/}"
      if type -- "$n" >/dev/null 2>&1; then r=1
      else d=$(pwd)
        while :; do
          if [ -e "$d/node_modules/.bin/$n" ] || [ -e "$d/node_modules/.bin/$n.cmd" ] || [ -e "$d/node_modules/$b" ]; then r=1; break; fi
          u="\${d%/*}"; [ -z "$u" ] || [ "$u" = "$d" ] && break; d=$u
        done
      fi ;;
    dockerimg:*) t="\${k#dockerimg:}"; r=1
      if type docker >/dev/null 2>&1; then
        o=$(docker image inspect -- "$t" 2>&1 >/dev/null) || { case "$o" in *"o such image"*) r=0 ;; esac; }
      fi ;;
    pymod:*) t="\${k#pymod:}"; i="\${t%%:*}"; m="\${t#*:}"
      "$i" -c 'import importlib.util,sys; sys.exit(0 if importlib.util.find_spec(sys.argv[1]) else 3)' "$m" >/dev/null 2>&1
      [ $? -eq 3 ] || r=1 ;;
    *) if w=$(type -- "$k" 2>&1 >/dev/null); then r=1; w=""; fi ;;
  esac
  printf '%s\\036%s\\036%s\\037' "$k" "$r" "$w"
done`;

const PROBE_PS = `$ks = $env:CHECK_PROBES -split [char]0x1f
foreach ($k in $ks) {
  if ($k -eq '') { continue }
  $r = 0; $w = ''
  if ($k.StartsWith('path:')) {
    if (Test-Path -LiteralPath $k.Substring(5)) { $r = 1 }
  } elseif ($k.StartsWith('gitcmd:')) {
    $s = $k.Substring(7)
    $out = & git --list-cmds=main,others,alias,parse-opt 2>$null
    if ($out -contains $s) { $r = 1 }
    else { try { $null = Get-Command ("git-" + $s) -ErrorAction Stop; $r = 1 } catch {} }
  } elseif ($k.StartsWith('gitref:')) {
    $f = $k.Substring(7)
    $null = & git rev-parse --verify --quiet $f 2>$null
    if ($LASTEXITCODE -eq 0) { $r = 1 }
    else { $null = & git ls-files --error-unmatch -- $f 2>$null; if ($LASTEXITCODE -eq 0) { $r = 1 } }
    if ($r -eq 0) { $rr = & git for-each-ref --count=1 --format=x "refs/remotes/*/$f" 2>$null; if ($rr) { $r = 1 } }
  } elseif ($k.StartsWith('cddir:')) {
    if (Test-Path -Path $k.Substring(6) -PathType Container) { $r = 1 }
  } elseif ($k.StartsWith('gitremote:')) {
    $out = & git remote 2>$null
    if (($out -contains $k.Substring(10)) -or (Test-Path -LiteralPath $k.Substring(10))) { $r = 1 }
  } elseif ($k.StartsWith('script:')) {
    $t = $k.Substring(7); $i = $t.IndexOf(':'); $kind = $t.Substring(0, $i); $f = $t.Substring($i + 1)
    $xs = if ($kind -eq 'node') { @('', '.js', '.mjs', '.cjs', '.json', '.node', '.ts', '.mts', '.cts') } else { @('') }
    foreach ($x in $xs) { if (Test-Path -LiteralPath ($f + $x)) { $r = 1; break } }
    if ($r -eq 0 -and $kind -eq 'sh') { try { $null = Get-Command $f -CommandType Application -ErrorAction Stop; $r = 1 } catch {} }
  } elseif ($k.StartsWith('npxbin:')) {
    $b = $k.Substring(7); $n = ($b -split '/')[-1]
    try { $null = Get-Command $n -ErrorAction Stop; $r = 1 } catch {}
    $d = (Get-Location).ProviderPath
    while ($r -eq 0 -and $d) {
      $m = Join-Path $d 'node_modules'
      if ((Test-Path -LiteralPath (Join-Path (Join-Path $m '.bin') $n)) -or (Test-Path -LiteralPath (Join-Path (Join-Path $m '.bin') ($n + '.cmd'))) -or (Test-Path -LiteralPath (Join-Path $m $b))) { $r = 1 }
      $d = Split-Path $d -Parent
    }
  } elseif ($k.StartsWith('dockerimg:')) {
    $r = 1
    if (Get-Command docker -ErrorAction SilentlyContinue) {
      $o = & docker image inspect -- $k.Substring(10) 2>&1 | Out-String
      if ($LASTEXITCODE -ne 0 -and $o -match 'o such image') { $r = 0 }
    }
  } elseif ($k.StartsWith('pymod:')) {
    $t = $k.Substring(6); $i = $t.IndexOf(':'); $exe = $t.Substring(0, $i); $m = $t.Substring($i + 1)
    $r = 1
    try { & $exe -c 'import importlib.util,sys; sys.exit(0 if importlib.util.find_spec(sys.argv[1]) else 3)' $m *> $null; if ($LASTEXITCODE -eq 3) { $r = 0 } } catch {}
  } else {
    try { $null = Get-Command $k -ErrorAction Stop; $r = 1 } catch { $w = $_.Exception.Message }
  }
  [Console]::Out.Write($k + [char]0x1e + $r + [char]0x1e + $w + [char]0x1f)
}`;

// Async spawn only (not spawnSync): this runs AFTER the first server round,
// and spawnSync after async I/O trips a libuv teardown assertion on Windows.
// The PowerShell Claude Code's PowerShell tool runs, found the way Claude Code
// finds it (read from its own code, 10 Oct): pwsh on PATH; then PowerShell 7 in
// Program Files, the WindowsApps alias (followed to its target), and .dotnet
// tools; then powershell on PATH; then the stock 5.1. Always -NoProfile, as the
// tool runs it: measured, the tool's session and a fresh `pwsh -NoProfile`
// name the same 1,854 commands.
function isFileAt(p) { try { return p && statSync(p).isFile() ? p : null; } catch { return null; } }
function onPath(name) {
  for (const d of (process.env.PATH || "").split(";")) {
    const p = d ? isFileAt(join(d, name + ".exe")) : null;
    if (p) return p;
  }
  return null;
}
function claudePowerShell() {
  const e = process.env;
  const alias = () => { try { return isFileAt(readlinkSync(join(e.LOCALAPPDATA, "Microsoft", "WindowsApps", "pwsh.exe"))); } catch { return null; } };
  const seven = onPath("pwsh")
    ?? (e.ProgramFiles ? isFileAt(join(e.ProgramFiles, "PowerShell", "7", "pwsh.exe")) : null)
    ?? (e.LOCALAPPDATA ? alias() : null)
    ?? (e.USERPROFILE ? isFileAt(join(e.USERPROFILE, ".dotnet", "tools", "pwsh.exe")) : null);
  const five = onPath("powershell") ?? isFileAt(join(e.SYSTEMROOT || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"));
  return { chosen: seven ?? five, other: seven ? five : null };
}

function answerProbes(keys, cwd, shell) {
  const out = { probe: {}, why: {} };
  if (!Array.isArray(keys) || keys.length === 0) return Promise.resolve(out);
  const all = keys.filter(k => typeof k === "string" && k.length > 0 && k.length < 600).slice(0, 16);
  // npm scripts are answered here, from package.json, not by a shell.
  const local = {};
  for (const k of all.filter(k => k.startsWith("npmscript:"))) {
    const a = npmScriptAnswer(k.slice(10), cwd);
    if (a !== null) local[k] = a;
  }
  const safe = all.filter(k => !k.startsWith("npmscript:"));
  const merge = (r) => { Object.assign(r.probe, local); return r; };
  if (safe.length === 0) return Promise.resolve(merge(out));
  if (shell !== "powershell") {
    const bash = bashPath();
    if (!bash) return Promise.resolve(merge(out));
    return runProbe(bash, ["-c", PROBE_SH, "check", ...safe], { cwd }).then(merge);
  }
  // PowerShell: the shell Claude Code runs answers; a key the server prefixes
  // "other:" is answered by the other installed PowerShell, or, when there is
  // no other, repeated as "not found".
  const ps = (exe, ks) => runProbe(exe, ["-NoProfile", "-NonInteractive", "-Command", PROBE_PS],
    { cwd, env: { ...process.env, CHECK_PROBES: ks.join("\x1f") } });
  const { chosen, other } = claudePowerShell();
  if (!chosen) return Promise.resolve(merge(out));
  const mine = safe.filter(k => !k.startsWith("other:"));
  const theirs = safe.filter(k => k.startsWith("other:")).map(k => k.slice(6));
  return Promise.all([
    mine.length ? ps(chosen, mine) : Promise.resolve({ probe: {}, why: {} }),
    theirs.length && other ? ps(other, theirs) : Promise.resolve({ probe: {}, why: {} }),
  ]).then(([a, b]) => {
    for (const k of theirs) a.probe["other:" + k] = other ? b.probe[k] : false;
    for (const k of Object.keys(a.probe)) if (a.probe[k] === undefined) delete a.probe[k];
    return merge(a);
  });
}

function runProbe(exe, args, opts) {
  const out = { probe: {}, why: {} };
  let child;
  try { child = spawn(exe, args, opts); } catch { return Promise.resolve(out); }
  return new Promise((resolve) => {
    let stdout = "";
    const done = () => {
      try {
        for (const rec of stdout.split("\x1f")) {
          if (!rec) continue;
          const [key, val, why] = rec.split("\x1e");
          if (!key || (val !== "0" && val !== "1")) continue;
          out.probe[key] = val === "1";
          if (val === "0" && why) out.why[key] = why.replace(/[\x00-\x1f\x7f]/g, " ").trim().slice(0, 200);
        }
      } catch {}
      resolve(out);
    };
    const timer = setTimeout(() => { try { child.kill(); } catch {} done(); }, 8000);
    child.stdout.on("data", (c) => { stdout += c; });
    child.on("error", () => { clearTimeout(timer); resolve(out); });
    child.on("close", () => { clearTimeout(timer); done(); });
  });
}

// --- MAIN HOOK ENTRY -------------------------------------------------------

function post(hookKey, payload, ms = 5000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return fetch(API, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-GOL-CLIENT-ID": hookKey, "User-Agent": "c/" + VERSION },
    body: JSON.stringify(payload),
    signal: controller.signal,
  }).finally(() => clearTimeout(timer));
}

// The conversation with the server for one check: send the facts; while it
// asks, answer (existence probes from the shell, parses from the parsers) and
// send again. Every answer is cumulative, so each round stands on its own.
async function consult(hookKey, body, ctx, shell, cwd, preParsed = {}) {
  let parsed = { ...preParsed }, probe = null, why = {};
  const asked = new Set();
  let res, d;
  for (let round = 0; round < 6; round++) {
    const payload = { ...body, parsed };
    if (probe) { payload.probe = probe; payload.probe_why = why; delete payload.probe_ok; }
    res = await post(hookKey, payload);
    d = await res.json();
    if (!res.ok || d.verdict !== "probe") break;
    let fresh = false;
    const keys = (Array.isArray(d.probe) ? d.probe : []).filter(k => typeof k === "string" && !asked.has(k));
    if (keys.length) {
      for (const k of keys) asked.add(k);
      const a = await answerProbes(keys, cwd, shell);
      probe = { ...(probe || {}) };
      for (const k of keys) {
        if (k in a.probe) { probe[k] = a.probe[k]; if (a.why[k]) why[k] = a.why[k]; }
      }
      fresh = true;
    }
    const reqs = (Array.isArray(d.parse) ? d.parse : []).filter(q => q && typeof q.id === "string" && !(q.id in parsed));
    if (reqs.length) { Object.assign(parsed, answerParse(reqs, ctx)); fresh = true; }
    if (!fresh) break;
  }
  return { res, d };
}

function verdictOut(f, res, d, restore = (s) => s) {
  if (!res.ok) {
    if (res.status === 429 || /rate limit/i.test(d.reason || d.error || "")) { outCreditsExhausted(f, NOTICE.rate_limit, "rate_limit"); return; }
    if (res.status >= 500) { outCreditsExhausted(f, NOTICE.server_error(res.status), "server_error"); return; }
    if (res.status === 402) { outCreditsExhausted(f, NOTICE.credits(d.daily_free || 120), "credits_exhausted"); return; }
    outCreditsExhausted(f, NOTICE.key_rejected, "key_rejected");
    return;
  }
  // Anything but a deny passes: a question left open is no verdict.
  if (d.verdict !== "invalid") { out(f, true); return; }
  out(f, false, restore(d.reason || "check: server returned a deny with no reason attached. Report at golproductions.com/console if this persists."));
}

// --- TURNS AND HELPERS ------------------------------------------------------
//
// The table's helpers: which message an action belongs to (per session),
// parsing a JSON-string argument, an apply_patch that adds a file, and edits
// applied to a file as it is now. What each tool sends is the table's job.
const TURNS = join(homedir(), ".check", "turns");
function rememberTurn(session, id) {
  try { mkdirSync(TURNS, { recursive: true }); writeFileSync(join(TURNS, safeId(session) || "none"), String(id)); } catch {}
}
function recallTurn(session) {
  const s = safeId(session);
  try { const id = readFileSync(join(TURNS, s || "none"), "utf8").trim(); if (id) return id; } catch {}
  // No message seen for this session: one message per session per day (the
  // server still bounds it at 500 checks and 12 hours).
  return s ? s + "-" + new Date().toISOString().slice(0, 10) : null;
}
function parseArgs(a) {
  if (a && typeof a === "object") return a;
  if (typeof a === "string") { try { const j = JSON.parse(a); return j && typeof j === "object" ? j : {}; } catch {} }
  return {};
}
// Codex apply_patch: only a patch that adds whole files has a known result.
function patchAdds(patch) {
  if (typeof patch !== "string" || !/^\*\*\* Begin Patch/m.test(patch)) return null;
  const ops = patch.split("\n").filter(l => /^\*\*\* (Add|Update|Delete) File: /.test(l));
  if (!ops.length || ops.some(l => !l.startsWith("*** Add File: "))) return null;
  const files = [];
  let cur = null;
  for (const line of patch.split("\n")) {
    if (line.startsWith("*** Add File: ")) { cur = { path: line.slice(14).trim(), lines: [] }; files.push(cur); continue; }
    if (/^\*\*\* (End Patch|End of File)/.test(line)) { cur = null; continue; }
    if (cur) { if (!line.startsWith("+")) return null; cur.lines.push(line.slice(1)); }
  }
  return files.map(f => ({ path: f.path, content: f.lines.join("\n") + "\n" }));
}
// Windsurf / Devin pre_write_code: the edits, applied in order to the file as
// it is now (a new file is one edit from "").
function applyEdits(path, edits) {
  if (!Array.isArray(edits) || !edits.length) return null;
  let text = "";
  try { text = existsSync(path) ? readFileSync(path, "utf8") : ""; } catch { return null; }
  for (const e of edits) {
    if (!e || typeof e.old_string !== "string" || typeof e.new_string !== "string") return null;
    if (e.old_string === "") { if (text !== "") return null; text = e.new_string; continue; }
    const at = text.indexOf(e.old_string);
    if (at < 0) return null;
    text = text.slice(0, at) + e.new_string + text.slice(at + e.old_string.length);
  }
  return text;
}
const CHECK_DIR = join(homedir(), ".check");
// --- ROUTING (thin client, 15 Oct) ----------------------------------------
//
// How each AI tool asks, and how it expects the answer, is the server's
// format table, and it stays there. This client sends the shape of a hook's
// input (each field's place, type and length; no values) to /route. The
// server applies its table and may ask for: a hash of a short field it
// compares to a known name (never of a long one, so never file contents);
// a field holding JSON, unpacked here; one of the transforms below, run
// here. It answers with the route: which tool, which event, where the
// command, file and IDs are, and how this tool expects to be answered.
// A route is kept for a day per input shape, so it is asked once, not on
// every action. With no route (offline), the action goes ahead silently.
let REPLIES = {}, MESSAGE_SKIP = null;
const ROUTES_DIR = join(CHECK_DIR, "routes");
function writeAtomic(path, text) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = path + "." + process.pid + ".tmp";
  writeFileSync(tmp, text);
  try { renameSync(tmp, path); } catch (e) { try { unlinkSync(tmp); } catch {} throw e; }
}

function at(o, ptr) {
  let v = o;
  for (const k of String(ptr).split("/").slice(1)) { if (v === null || typeof v !== "object") return undefined; v = v[k]; }
  return v;
}
function setAt(o, ptr, value) {
  const ks = String(ptr).split("/").slice(1), last = ks.pop();
  let v = o;
  for (const k of ks) { if (v === null || typeof v !== "object") return; v = v[k]; }
  if (v && typeof v === "object") v[last] = value;
}
function part(x, o, ctx) {
  if (x && typeof x === "object") {
    if (Array.isArray(x.alt)) { for (const a of x.alt) { const v = part(a, o, ctx); if (v) return v; } return ""; }
    if (Array.isArray(x.join)) return joinParts(x.join, o, ctx);
    return "";
  }
  if (x === "$now") return String(Date.now());
  if (x === "$session") return ctx.session || "";
  if (typeof x === "string" && x.startsWith("/")) { const v = at(o, x); return v === undefined || v === null || typeof v === "object" ? "" : String(v); }
  return typeof x === "string" ? x : "";
}
function joinParts(list, o, ctx) { return Array.isArray(list) ? list.map(x => part(x, o, ctx)).join("") : ""; }
function val(x, o) {
  if (x && typeof x === "object" && Array.isArray(x.alt)) {
    for (const a of x.alt) { const v = typeof a === "string" && a.startsWith("/") ? at(o, a) : a; if (v !== undefined && v !== null && v !== "") return v; }
    return undefined;
  }
  return typeof x === "string" && x.startsWith("/") ? at(o, x) : x;
}
// The table's named helpers. A helper with no result: try the next rule.
const TRANSFORMS = {
  json_args(o, t) { setAt(o, t.p, parseArgs(at(o, t.p))); return true; },
  patch_adds(o, t) {
    const adds = patchAdds(at(o, t.from));
    if (!adds || adds.length !== 1) return false;
    const cwd = at(o, t.cwd);
    o.$t.file_path = /^([A-Za-z]:[\\/]|\/)/.test(adds[0].path) ? adds[0].path : join(typeof cwd === "string" && cwd ? cwd : process.cwd(), adds[0].path);
    o.$t.content = adds[0].content;
    return true;
  },
  apply_edits(o, t) {
    const c = applyEdits(at(o, t.path), at(o, t.edits));
    if (c === null) return false;
    o.$t.content = c;
    return true;
  },
};
const sha16 = (v) => createHash("sha256").update(String(v)).digest("hex").slice(0, 16);
// The shape: each field's place, type and length (numbers and true/false as
// they are). No string ever leaves this way.
function shapeOf(o, prefix = "", out = {}, depth = 0) {
  if (Object.keys(out).length > 400 || depth > 6) return out;
  const t = o === null ? "null" : Array.isArray(o) ? "array" : typeof o;
  if (prefix) out[prefix] = t === "string" ? { t, n: o.length } : t === "number" || t === "boolean" ? { t, v: o } : { t };
  if (t === "object") for (const [k, v] of Object.entries(o)) if (!k.includes("/")) shapeOf(v, prefix + "/" + k, out, depth + 1);
  return out;
}
// Each rule's own copy of the input, for its transforms.
const COPIES = new Map();
const copyFor = (raw, r) => { if (!COPIES.has(r)) COPIES.set(r, { ...structuredClone(raw), $t: {} }); return COPIES.get(r); };
function routeAnswer(raw, q) {
  const a = q && q.a && typeof q.a === "object" ? q.a : {};
  if (q.q === "hash") {
    const v = at(a.r !== undefined ? copyFor(raw, a.r) : raw, a.p);
    return typeof v === "string" && v.length <= 64 ? { h: sha16(v), hl: sha16(v.toLowerCase()) } : null;
  }
  if (q.q === "json") {
    const o = copyFor(raw, a.r);
    if (typeof a.p !== "string" || typeof at(o, a.p) !== "string") return { ok: false };
    TRANSFORMS.json_args(o, { p: a.p });
    return { ok: true, shape: shapeOf(at(o, a.p), a.p) };
  }
  if (q.q === "transform") {
    if (!["patch_adds", "apply_edits"].includes(a.op)) return null;
    const o = copyFor(raw, a.r);
    let ok = false;
    try { ok = !!TRANSFORMS[a.op](o, a); } catch { ok = false; }
    return ok ? { ok: true, shape: shapeOf(o.$t, "/$t") } : { ok: false };
  }
  return null;
}
async function postRoute(key, body, ms = 4000) {
  const ac = new AbortController(), t = setTimeout(() => ac.abort(), ms);
  try {
    const r = await fetch(BASE + "/route", { method: "POST", headers: { "Content-Type": "application/json", ...(key ? { "X-GOL-CLIENT-ID": key } : {}), "User-Agent": "c/" + VERSION }, body: JSON.stringify(body), signal: ac.signal });
    return r.ok ? await r.json() : null;
  } catch { return null; } finally { clearTimeout(t); }
}
// The route for this input: from the day's cache if the same questions get
// the same answers, else from the server. null: no route (offline).
async function routeOf(raw, key) {
  const shape = shapeOf(raw);
  const sig = sha16(JSON.stringify(Object.entries(shape).map(([p, l]) => [p, l.t])) + "|" + platform());
  const file = join(ROUTES_DIR, sig + ".json");
  const keyOfAnswers = (ans) => sha16(JSON.stringify(Object.entries(ans).sort().map(([id, v]) => [id, v && v.shape ? Object.entries(v.shape).map(([p, l]) => [p, l.t]) : v])));
  try {
    const c = JSON.parse(readFileSync(file, "utf8"));
    if (Date.now() - c.at < 86400000 && Array.isArray(c.asks)) {
      const ans = {};
      for (const q of c.asks) ans[q.id] = routeAnswer(raw, q);
      const hit = c.routes && c.routes[keyOfAnswers(ans)];
      if (hit) return hit;
    }
  } catch {}
  const answers = {}, asked = [];
  for (let round = 0; round < 6; round++) {
    const d = await postRoute(key, { shape, os: platform(), v: VERSION, answers });
    if (!d) return null;
    if (d.route) {
      try {
        let c = {};
        try { c = JSON.parse(readFileSync(file, "utf8")); } catch {}
        if (!(Date.now() - (c.at || 0) < 86400000)) c = { at: Date.now(), asks: [], routes: {} };
        const ids = new Set(c.asks.map(q => q.id));
        for (const q of asked) if (!ids.has(q.id)) c.asks.push(q);
        const all = {};
        for (const q of c.asks) all[q.id] = q.id in answers ? answers[q.id] : routeAnswer(raw, q);
        c.routes[keyOfAnswers(all)] = d.route;
        writeAtomic(file, JSON.stringify(c));
      } catch {}
      return d.route;
    }
    const fresh = (Array.isArray(d.ask) ? d.ask : []).filter(q => q && typeof q.id === "string" && !(q.id in answers));
    if (!fresh.length) return null;
    for (const q of fresh.slice(0, 24)) { answers[q.id] = routeAnswer(raw, q); asked.push(q); }
  }
  return null;
}
// The input in the gate's one shape (Claude Code's), as the route says.
function applyRoute(raw, route) {
  const fmt = typeof route.fmt === "string" ? route.fmt : "claude";
  REPLIES = route.replies && typeof route.replies === "object" ? route.replies : {};
  MESSAGE_SKIP = typeof route.message_skip === "string" ? route.message_skip : null;
  if (route.native) return { fmt, p: raw };
  if (route.pass || (route.kind !== "message" && route.kind !== "action")) return { fmt, pass: true };
  const o = Number.isInteger(route.rule) ? copyFor(raw, route.rule) : { ...raw, $t: {} };
  const ctx = { session: joinParts(route.session, o, {}) };
  const set = {};
  for (const [k, x] of Object.entries(route.set || {})) set[k] = val(x, o);
  if (route.kind === "message") {
    MESSAGE_SKIP = typeof route.message_skip === "string" ? route.message_skip : null;
    const id = joinParts(route.msgid, o, ctx);
    if (route.remember && id) rememberTurn(ctx.session, id);
    return { fmt, p: { hook_event_name: "UserPromptSubmit", prompt_id: id, prompt: set.prompt } };
  }
  const prompt_id = route.prompt_id === "recall" ? recallTurn(ctx.session) : Array.isArray(route.prompt_id) ? joinParts(route.prompt_id, o, ctx) : null;
  const ti = {};
  for (const k of ["command", "file_path", "content", "old_string", "new_string", "replace_all"]) if (set[k] !== undefined) ti[k] = set[k];
  return { fmt, p: { hook_event_name: "PreToolUse", tool_name: typeof route.tool === "string" ? route.tool : undefined, tool_input: ti, cwd: typeof set.cwd === "string" ? set.cwd : undefined, prompt_id } };
}

// (This copy ships inside a plugin: it never downloads or replaces code.
// Its updates come as new plugin versions.)

let FMT = "claude";

// --- MESSAGES AND RECEIPTS -------------------------------------------------
//
// Billing is one charge per message the user sends. This tells the server
// "a message happened": the key and Claude Code's prompt_id, nothing else.
// The prompt text is read only here, on this machine, to skip the messages
// Claude Code starts by itself (task results, helper messages). Nothing is
// printed, so nothing is added to the AI's context. Any failure is silent.
// Which messages a tool starts by itself: the table's message_skip.
function startedByTool(prompt) {
  try { return !!MESSAGE_SKIP && new RegExp(MESSAGE_SKIP).test(String(prompt || "")); } catch { return false; }
}
async function onMessage(p) {
  process.exitCode = 0;
  try {
    if (typeof p.prompt_id !== "string" || !p.prompt_id) return;
    if (startedByTool(p.prompt)) return;
    const key = getClientId();
    if (!key) return;
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 3000);
    await fetch(API.replace("/preflight", "/message"), {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-GOL-CLIENT-ID": key, "User-Agent": "c/" + VERSION },
      body: JSON.stringify({ prompt_id: p.prompt_id.slice(0, 160), channel: "npm", platform: FMT }),
      signal: ctl.signal,
    }).catch(() => {});
    clearTimeout(t);
  } catch {}
}

// When Claude finishes a response: show the user what Check did in it, in
// the machine's words. Shown to the user only, never to the AI.
function onStop(p) {
  process.exitCode = 0;
  try {
    if (p.stop_hook_active) return;
    const msg = receiptFor(p.prompt_id);
    if (msg) process.stdout.write(JSON.stringify({ systemMessage: msg }));
  } catch {}
}


// --- THE THIN CLIENT (15 Oct) ------------------------------------------------
//
// This client decides nothing and chooses nothing. It tells the server what
// the AI is about to do, then answers the server's questions, one fixed type
// each, until the server gives a verdict. A question of any other type, or one
// that fails its type's safety rule, is answered null (no answer).
//
// The safety rules, which are this client's own and never the server's:
//  - The bash readers (bashn, bashwords, bashsubst, bashcanon) run nothing:
//    each text passes bash -n before it is read (see PRE_ENV above).
//  - psparse runs PowerShell's parser only. psbind calls a stand-in that only
//    prints what PowerShell bound, and only for text from the AI's command.
//  - readtool and scriptcheck run something, so they run only text that is in
//    the command the AI is about to run anyway, only a read-only tool or an
//    interpreter's check-only flag, never an option that loads code, and with
//    output thrown away.
//  - Nothing else runs: copysize, dockerimage, dir and the rest only look.
// Credentials never leave: answers carry redacted text, as commands always did.

const ST = { raw: null, red: "", cwd0: null, tool: null, after: null, words: new Set(), ctx: { command: null, cwd: null, read: {}, canon: {} } };

// The scope rule. Every name the server asks about (a program, a folder, a
// path, a branch, a package, an image) must be in the command the AI is about
// to run, or in one of this machine's own readings of it. So a server that
// was taken over still learns nothing about this machine that the command
// did not already name: it cannot map folders, list programs or probe files.
function inScope(name) {
  if (typeof name !== "string" || !name || name.length > 600 || ST.raw === null) return false;
  if (ST.raw.includes(name)) return true;
  if (ST.words.has(name)) return true;
  for (const w of ST.words) if (w.includes(name)) return true;
  return false;
}
const remember = (recs) => { if (Array.isArray(recs)) for (const r of recs) if (Array.isArray(r)) for (const w of r) if (typeof w === "string" && ST.words.size < 20000) ST.words.add(w); };
// A probe key is "type:name" (or a bare program name); pymod names two.
function keyInScope(k) {
  const key = k.startsWith("other:") ? k.slice(6) : k;
  const m = key.match(/^(path|gitcmd|gitref|cddir|gitremote|script|npxbin|dockerimg|pymod|npmscript):([\s\S]*)$/);
  if (!m) return !key.includes(":") && inScope(key);
  if (m[1] === "pymod") { const i = m[2].indexOf(":"); return i > 0 && inScope(m[2].slice(0, i)) && inScope(m[2].slice(i + 1)); }
  if (m[1] === "script") { const i = m[2].indexOf(":"); return i > 0 && inScope(m[2].slice(i + 1)); }
  return inScope(m[2]);
}

// The server only ever sees the redacted command. A text it names is mapped
// back to the machine's own text: the whole command, or a part of it.
function resolveText(text) {
  if (typeof text !== "string" || ST.raw === null) return null;
  if (text === ST.red) return ST.raw;
  if (ST.raw.includes(text) && redact(text) === text) return text;
  if (ST.red !== ST.raw && ST.raw.length <= 200000) {
    // Each redaction tag stands for some text: find the part of the command
    // that redacts to exactly what the server named.
    const TAG = /(\[(?:SECRET|GITHUB_TOKEN|NPM_TOKEN|SLACK_TOKEN|AWS_KEY|GOOGLE_KEY|JWT|PRIVATE_KEY|EMAIL|CARD_LIKE)\]|Bearer \[TOKEN\])/;
    const parts = text.split(TAG);
    if (parts.length > 1 && parts.length < 40) {
      const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const re = new RegExp(parts.map((p, i) => i % 2 ? "([\\s\\S]+?)" : esc(p)).join(""), "g");
      for (const m of ST.raw.matchAll(re)) if (redact(m[0]) === text) return m[0];
    }
  }
  return null;
}
// A working folder named as cd steps from the real one, resolved here.
function resolveCwd(cd, ps) {
  let dir = ST.cwd0 && existsSync(ST.cwd0) ? ST.cwd0 : process.cwd();
  const win = platform() === "win32";
  for (const t of Array.isArray(cd) ? cd.slice(0, 8) : []) {
    if (typeof t !== "string" || !t || t.startsWith("-") || t.startsWith("~") || /[*?\[\]{}$`]/.test(t) || !inScope(t)) return null;
    let abs;
    if (!ps && win) { const conv = bashToWin([t], dir); if (!conv) return null; abs = conv[0]; }
    else abs = (win ? pathWin32 : pathPosix).resolve(dir, t);
    try { if (!statSync(abs).isDirectory()) return null; } catch { return null; }
    dir = abs;
  }
  return dir;
}
const wordOut = (w) => w.length > 1000 ? "${LONG}" : redact(w) === w ? w : "${REDACTED}";
const recsOut = (recs) => Array.isArray(recs) ? recs.slice(0, 300).map(r => Array.isArray(r) ? r.slice(0, 64).map(wordOut) : null) : null;

const SAFE_READ_SH = new Set(["cat", "head", "tail", "wc", "ls"]);
const SAFE_READ_PS = new Set(["get-content", "gc", "cat", "type", "get-childitem", "gci", "ls", "dir"]);
const CHECK_FLAG = { node: "--check", bash: "-n", sh: "-n", ruby: "-c", php: "-l" };
const RUNS_NOTHING = /[$`|<>(){}*?\[\]%;&\r\n]|\\$/;
const NODE_LOADS = /^(-e|-p|--eval|--print|-r|--require|--import|--loader|--experimental-loader|-i|--interactive|--env-file\S*|--inspect\S*|--test\S*|--watch\S*|--run)(=|$)/;
const ASK_MS = 1500;
// An interpreter's report, cut to its message lines: a line that quotes the
// script (node's source line and caret, ruby's excerpt) never leaves.
const MESSAGE_LINE = /(?:\b\w*Error\b|\berror\b|No such file or directory|Could not open input file|Cannot find|not found)/i;
const messageLines = (t) => redact(String(t || "")).split(/\r?\n/).filter(l => MESSAGE_LINE.test(l) && !/^\s*\^/.test(l)).join("\n").slice(0, 2000);

function runIn(cwd, ps, line) {
  if (ps) return spawnSync("powershell", ["-NoProfile", "-NonInteractive", "-Command", line], { cwd, timeout: ASK_MS, encoding: "utf8", windowsHide: true });
  const bash = bashPath();
  return bash ? spawnSync(bash, ["-c", line], { cwd, timeout: ASK_MS, encoding: "utf8", windowsHide: true }) : null;
}

function measureCopy(srcs, dest, base) {
  const abs = (x) => (platform() === "win32" ? pathWin32 : pathPosix).resolve(base, x);
  const d = abs(dest);
  try { if (statSync(d).isDirectory() && readdirSync(d).length) return null; } catch {}
  let probe = d;
  while (!existsSync(probe)) { const up = dirname(probe); if (up === probe) break; probe = up; }
  let free;
  try { const sf = statfsSync(probe); free = sf.bavail * sf.bsize; } catch { return null; }
  const deadline = Date.now() + COPY_WALK_MS;
  let bytes = 0, over = false;
  for (const s of srcs) {
    const t = treeBytes(abs(s), free - bytes, deadline);
    if (!t) return null;
    bytes += t.bytes;
    if (t.over) { over = true; break; }
  }
  return { shown: redactPath(d), bytes, free, over };
}

function dockerHelp(sub) {
  const ver = (() => { try { const r = spawnSync("docker", ["--version"], { timeout: 3000, encoding: "utf8", windowsHide: true }); return r.status === 0 ? String(r.stdout).trim() : null; } catch { return null; } })();
  if (!ver) return null;
  const file = join(homedir(), ".check", "docker-help-" + sub + ".json");
  try { const c = JSON.parse(readFileSync(file, "utf8")); if (c.ver === ver && typeof c.help === "string") return c; } catch {}
  let help;
  try { const r = spawnSync("docker", [sub, "--help"], { timeout: 3000, encoding: "utf8", windowsHide: true }); if (r.status !== 0) return null; help = String(r.stdout || "").slice(0, 60000); } catch { return null; }
  const out = { ver, help };
  try { mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, JSON.stringify(out)); } catch {}
  return out;
}

const ANSWER = {
  dir: (a) => ({ ok: !!resolveCwd(a.cd, !!a.ps) }),
  bashn: (a) => {
    const cwd = resolveCwd(a.cd, false); if (!cwd) return null;
    return runParser("bash", resolveText(a.text) ?? a.text, null, [], cwd);
  },
  bashwords: (a) => {
    const cwd = resolveCwd(a.cd, false); if (!cwd || typeof a.text !== "string") return null;
    const lex = bashWords(resolveText(a.text) ?? a.text, cwd, !!a.asRun, !!a.dollar);
    if (a.store === "t" || a.store === "r") ST.ctx.read[a.store] = lex ? lex.recs : null;
    if (lex) remember(lex.recs);
    return lex ? { recs: a.store ? redactRecs(lex.recs) : recsOut(lex.recs), complete: !!lex.complete } : null;
  },
  bashsubst: (a) => {
    const cwd = resolveCwd(a.cd, false); if (!cwd || typeof a.text !== "string") return null;
    const text = resolveText(a.text) ?? a.text;
    let r = null;
    for (let k = 0; k < 3; k++) { r = bashScript(SUBST_SH, text, cwd); if (!r || recordsWhole(r.stdout)) break; r = null; }
    if (!r) return null;
    return [...(r.stdout || "").matchAll(/\x1d([^\x1f]*)\x1f([01]*)\x1e/g)].slice(0, 64).map(m => [redact(m[1]), m[2]]);
  },
  bashcanon: (a) => {
    const cwd = resolveCwd(a.cd, false); if (!cwd || typeof a.text !== "string") return null;
    const lines = canonLines(resolveText(a.text) ?? a.text, cwd, !!a.asRun);
    if (a.store === "t" || a.store === "r") ST.ctx.canon[a.store] = lines;
    return lines ? lines.slice(0, 4000).map(l => redact(l)) : null;
  },
  psparse: (a) => {
    if (typeof a.text !== "string") return null;
    const ps = psCommand(resolveText(a.text) ?? a.text);
    if (ps.lex) remember(ps.lex.recs);
    return { facts: ps.facts, recs: ps.lex ? recsOut(ps.lex.recs) : null };
  },
  psnames: (a) => a.cmdlet === "Copy-Item" ? [...(psNames("Copy-Item") || [])] : null,
  psbind: (a) => {
    if (a.cmdlet !== "Copy-Item") return null;
    const text = resolveText(a.text), cwd = resolveCwd(a.cd, true);
    if (!text || !cwd) return null;
    const calls = psBound(text, cwd, "Copy-Item");
    return Array.isArray(calls) ? calls.slice(0, 16).map(c => Object.fromEntries(Object.entries(c).map(([k, v]) => [k, v.slice(0, 16).map(x => redact(x))]))) : null;
  },
  copysize: (a) => {
    const cwd = resolveCwd(a.cd, true);
    if (!cwd || !Array.isArray(a.srcs) || typeof a.dest !== "string") return null;
    if ([a.dest, ...a.srcs].some(w => typeof w !== "string" || /[*?\[\]$]|\[[A-Z_]+\]/.test(w) || !inScope(w))) return null;
    return measureCopy(a.srcs.slice(0, 16), a.dest, cwd);
  },
  dockerhelp: (a) => ["pull", "run", "create"].includes(a.sub) ? dockerHelp(a.sub) : null,
  dockerimage: (a) => {
    if (typeof a.img !== "string" || !/^[a-z0-9][\w.\/:-]{0,254}$/i.test(a.img) || !inScope(a.img)) return null;
    const cwd = resolveCwd(a.cd, false) || undefined;
    try {
      const r = spawnSync("docker", ["image", "inspect", "--", a.img], { cwd, timeout: 4000, encoding: "utf8", windowsHide: true });
      if (r.error || r.status === null) return null;
      return { missing: r.status !== 0 && /No such image/i.test(String(r.stderr || "") + String(r.stdout || "")) };
    } catch { return null; }
  },
  readtool: (a) => {
    const text = resolveText(a.text), ps = !!a.ps, cwd = resolveCwd(a.cd, ps);
    if (!text || !cwd || text.length > 600 || RUNS_NOTHING.test(text)) return null;
    const verb = text.trim().split(/\s+/)[0].toLowerCase().replace(/\.exe$/, "");
    if (!(ps ? SAFE_READ_PS : SAFE_READ_SH).has(verb)) return null;
    let r; try { r = runIn(cwd, ps, ps ? text + " | Out-Null" : text + " >/dev/null"); } catch { return null; }
    if (!r || r.error || r.status === null) return null;
    return { status: r.status, err: redact(String(r.stderr || "")).slice(0, 2000) };
  },
  scriptcheck: (a) => {
    const flag = CHECK_FLAG[a.interp], ps = !!a.ps, cwd = resolveCwd(a.cd, ps);
    if (!flag || !cwd || typeof a.args !== "string" || !a.args || a.args.length > 600 || RUNS_NOTHING.test(a.args)) return null;
    const flat = (s) => s.trim().split(/\s+/).join(" ");
    if (ST.raw === null || !flat(ST.raw).includes(flat(a.interp + " " + a.args))) return null;
    const args = flat(a.args).split(" ");
    if (a.interp === "node") { for (const w of args) { if (!w.startsWith("-")) break; if (NODE_LOADS.test(w)) return null; } }
    if ((a.interp === "ruby" || a.interp === "php") && (args.length !== 1 || args[0].startsWith("-"))) return null;
    let r; try { r = runIn(cwd, ps, a.interp + " " + flag + " " + args.join(" ")); } catch { return null; }
    if (!r || r.error || r.status === null) return null;
    return { status: r.status, err: messageLines(r.stderr), out: messageLines(r.stdout) };
  },
  // Where this machine installs from: only when the AI is installing something.
  registries: () => ST.after || (ST.raw !== null && /\b(?:npm|npx|yarn|pnpm|bunx?|pip3?|pipx|uvx?|poetry|pdm|pipenv|cargo|gem|composer|dotnet)\b/i.test(ST.raw)) ? customRegistries() : null,
  importscan: async () => ST.after ? importScan(ST.after.path, ST.after.content) : null,
  // TypeScript runs once per check; its errors are kept here and handed out.
  tsdiags: () => {
    if (!ST.after) return null;
    if (ST.ts === undefined) ST.ts = tsFacts(ST.after.path, ST.after.content);
    return Array.isArray(ST.ts) ? ST.ts.map((d, i) => ({ i, code: d.code, line: d.line })) : null;
  },
  // Details for at most 5 errors per edit: the client's own privacy limit,
  // so little is told about the code. Which errors matter: the server's.
  tsdetail: (a) => {
    const d = Array.isArray(ST.ts) && Number.isInteger(a.i) ? ST.ts[a.i] : null;
    if (!d || !d.det) return null;
    ST.tsTold = ST.tsTold || new Set();
    if (!ST.tsTold.has(a.i) && ST.tsTold.size >= 5) return null;
    ST.tsTold.add(a.i);
    const nm = (x) => typeof x === "string" ? redact(x).slice(0, 100) : null;
    const libs = (l) => Array.isArray(l) ? l.slice(0, 16).map(x => typeof x === "string" ? x.slice(0, 100) : null) : [];
    return {
      msg: redact(String(d.det.msg || "")).slice(0, 300),
      ...(d.det.access ? { access: { name: nm(d.det.access.name), libs: libs(d.det.access.libs) } } : {}),
      ...(d.det.import ? { import: { lib: typeof d.det.import.lib === "string" ? d.det.import.lib.slice(0, 100) : null } } : {}),
      ...(d.det.prop ? { prop: { name: nm(d.det.prop.name), libs: libs(d.det.prop.libs) } } : {}),
    };
  },
};

async function answerAsks(asks) {
  const out = {};
  for (const q of (Array.isArray(asks) ? asks : []).slice(0, 24)) {
    if (!q || typeof q.id !== "string" || typeof q.q !== "string") continue;
    const fn = Object.prototype.hasOwnProperty.call(ANSWER, q.q) ? ANSWER[q.q] : null;
    let v = null;
    try { v = fn ? await fn(q.a && typeof q.a === "object" ? q.a : {}) : null; } catch { v = null; }
    out[q.id] = v === undefined ? null : v;
  }
  return out;
}

// The conversation for one check: send what happened; while the server asks,
// answer and send again. Every answer is cumulative.
const CHECK_LIMIT_MS = 20000;
async function consultThin(hookKey, body, shell) {
  const until = Date.now() + CHECK_LIMIT_MS;
  const answers = {}, parsed = {};
  let probe = null, why = {};
  const asked = new Set();
  let res, d;
  for (let round = 0; round < 14; round++) {
    if (Date.now() > until) break;
    const payload = { ...body, answers, parsed };
    if (probe) { payload.probe = probe; payload.probe_why = why; }
    res = await post(hookKey, payload);
    d = await res.json();
    if (!res.ok) break;
    if (d.verdict === "ask") {
      if (d.focus && typeof d.focus === "object") {
        ST.ctx.command = resolveText(d.focus.text);
        ST.ctx.cwd = resolveCwd(d.focus.cd, ST.tool === "PowerShell");
      }
      const fresh = (Array.isArray(d.ask) ? d.ask : []).filter(q => q && typeof q.id === "string" && !(q.id in answers));
      if (!fresh.length) break;
      Object.assign(answers, await answerAsks(fresh));
      continue;
    }
    if (d.verdict !== "probe") break;
    let more = false;
    const keys = (Array.isArray(d.probe) ? d.probe : []).filter(k => typeof k === "string" && !asked.has(k));
    if (keys.length) {
      for (const k of keys) asked.add(k);
      const a = await answerProbes(keys.filter(keyInScope), ST.ctx.cwd || ST.cwd0, shell);
      probe = { ...(probe || {}) };
      for (const k of keys) if (k in a.probe) { probe[k] = a.probe[k]; if (a.why[k]) why[k] = a.why[k]; }
      more = true;
    }
    const reqs = (Array.isArray(d.parse) ? d.parse : []).filter(q => q && typeof q.id === "string" && !(q.id in parsed));
    if (reqs.length) {
      // A file the server names must be one the command or the write names.
      const ok = reqs.filter(q => q.s?.k !== "file" || inScope(q.s.p));
      for (const q of reqs) if (!ok.includes(q)) parsed[q.id] = { c: null };
      Object.assign(parsed, answerParse(ok, ST.ctx)); more = true;
    }
    if (!more) break;
  }
  return { res, d };
}

async function main() {
  let f = "claude";
  try {
    const key0 = getClientId();
    let input = "";
    for await (const chunk of process.stdin) input += chunk;
    input = input.replace(/^﻿/, "").trim();
    if (!input) { process.stderr.write("check: no hook input on stdin. This entrypoint is for tool hooks.\n"); process.exit(0); }
    let p;
    try { p = JSON.parse(input); } catch {
      // Unreadable input has no shape: the empty one routes to Claude Code's words.
      const r0 = await routeOf({}, key0);
      if (r0) applyRoute({}, r0);
      outCreditsExhausted("claude", NOTICE.bad_input, "bad_input");
      return;
    }
    const route = await routeOf(p, key0);
    if (!route) { process.exitCode = 0; return; }
    const ad = applyRoute(p, route);
    FMT = f = ad.fmt;
    if (ad.pass) { out(f, true, "", true); return; }
    p = ad.p;
    if (p.hook_event_name === "PostToolUse") { process.exit(0); return; }
    const base = { thin: 1, platform: f, channel: "npm", v: VERSION, os: platform(), facts_ok: 1 };
    ST.cwd0 = p.cwd || null; ST.tool = p.tool_name; ST.ctx.cwd = ST.cwd0;
    if (p.hook_event_name === "PostToolUseFailure") {
      const command = p.tool_name === "Bash" && !p.is_interrupt && typeof p.tool_input?.command === "string" ? p.tool_input.command : "";
      const hookKey = getClientId();
      if (command && command.includes("\\") && hookKey) {
        try {
          ST.raw = command; ST.red = redact(command);
          const { res, d } = await consultThin(hookKey, { ...base, hook_event_name: "PostToolUseFailure", tool_name: "Bash", command: ST.red }, "bash");
          if (res.ok && typeof d.note === "string") process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "PostToolUseFailure", additionalContext: d.note } }));
        } catch {}
      }
      process.exit(0);
      return;
    }
    if (p.hook_event_name === "UserPromptSubmit") { await onMessage(p); say(f, "message"); return; }
    if (p.hook_event_name === "Stop") { onStop(p); return; }
    CURRENT_PROMPT = typeof p.prompt_id === "string" ? p.prompt_id : null;

    if (p.tool_name === "Write" || p.tool_name === "Edit" || p.tool_name === "NotebookEdit") {
      const after = contentAfter(p);
      const hookKey = getClientId();
      if (!after || !hookKey) { out(f, true); return; }
      ST.after = after;
      ST.ctx = { command: null, cwd: p.cwd, read: {}, canon: {}, after: after.content, path: after.path };
      const shown = redactPath(after.path);
      const body = {
        ...base, tool_name: p.tool_name,
        write: {
          name: redact(basename(String(after.path))), shown,
          size: typeof after.content === "string" ? after.content.length : 0,
          exists: (() => { try { return existsSync(after.path) ? 1 : 0; } catch { return null; } })(),
        },
      };
      if (CURRENT_PROMPT) body.prompt_id = CURRENT_PROMPT.slice(0, 160);
      const { res, d } = await consultThin(hookKey, body, "bash");
      verdictOut(f, res, d, (s) => s.split(shown).join(after.path));
      return;
    }

    const c = typeof p.tool_input?.command === "string" ? p.tool_input.command : null;
    if (!c) { out(f, true); return; }
    const hookKey = getClientId();
    if (!hookKey) { outCreditsExhausted(f, NOTICE.no_key, "no_key"); return; }
    ST.raw = c; ST.red = redact(c); ST.ctx.command = c;
    const body = { ...base, tool_name: p.tool_name, command: ST.red, cwd: redactPath(p.cwd || process.cwd()) };
    if (CURRENT_PROMPT) body.prompt_id = CURRENT_PROMPT.slice(0, 160);
    const { res, d } = await consultThin(hookKey, body, p.tool_name === "PowerShell" ? "powershell" : "bash");
    verdictOut(f, res, d);
  } catch {
    outCreditsExhausted(f, NOTICE.unreachable, "unreachable");
  }
}

main().catch(() => process.exit(0));
