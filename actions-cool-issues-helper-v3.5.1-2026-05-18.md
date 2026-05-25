# Supply Chain Compromise: actions-cool/issues-helper (All Tags)

## TL;DR

**All tags** for `actions-cool/issues-helper` have been compromised. Every tag — including all version tags and `latest` — was re-pointed to a single malicious commit authored on 2026-05-18. There is no safe tag to pin to. The injected code reads decrypted secrets directly from runner process memory, harvests GitHub Actions OIDC tokens, AWS credentials, NPM tokens, and more, then exfiltrates everything to `t.m-kosche.com`. It also injects persistent malicious hooks into Claude Code and VS Code configurations on the runner. **Remove the action from all workflows immediately** or pin to the last known-safe SHA `25379ae1ea683ac484497214db131ab8f003a52b`.

**External analysis:** StepSecurity published a concurrent investigation: [actions-cool/issues-helper GitHub Action Compromised — All Tags Point to Imposter Commit That Exfiltrates CI/CD Credentials](https://www.stepsecurity.io/blog/actions-cool-issues-helper-github-action-compromised-all-tags-point-to-imposter-commit-that-exfiltrates-ci-cd-credentials)

---

## Introduction

This report documents a confirmed active supply-chain compromise affecting `actions-cool/issues-helper`. Each tag was re-pointed to its own distinct malicious imposter commit, authored by `lijinke666`. **All tags in the repository point to malicious imposter commits** — there is no safe version tag. Any workflow referencing `actions-cool/issues-helper` at any tag that executed after 2026-05-18T19:11:08Z should be treated as fully compromised.

This is an active incident. Details may evolve as forensic analysis continues.

---

## Timeline

- **2026-05-18T19:11:08Z** — Coordinated tag drift begins. All tags were re-pointed to distinct malicious imposter commits within a 10-minute window, consistent with scripted, automated execution.

---

## Attack Analysis

### Execution Model Change

The first and most operationally significant change is in `action.yml`. The original action used a direct Node.js execution model:

```yaml
runs:
  using: node16
  main: 'dist/index.js'
```

The malicious commit replaces this with a composite action that installs the Bun runtime and executes a newly added, opaque 500 KB `index.js`:

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

The third step delegates to the same action at a hardcoded SHA. This two-stage design allows the malicious `index.js` to execute first — harvesting credentials — while the action continues to perform its legitimate issue-management function in the second stage. This significantly reduces the likelihood that affected users notice any behavioral change.

If `bun` is not present on the runner, the payload installs it silently before executing:

```bash
command -v bun >/dev/null 2>&1 || (curl -fsSL https://bun.sh/install | bash && export PATH=$HOME/.bun/bin:$PATH)
```

### Complete Source Replacement

All 68 original source files were deleted: the full TypeScript source tree (`src/`), tests, build scripts, CI workflows, documentation, and the prior compiled bundle (`dist/index.js`). The sole addition is the new 500 KB `index.js`. Deleting the source eliminates the auditable artifact and removes prior compiled bundles that security scanners may have already profiled.

### Runner Memory Scraping

The most dangerous capability in the payload is direct extraction of secrets from runner process memory. The malware spawns `python3` to read `/proc/<PID>/mem` — the address space of the **Runner.Worker process** — which holds all decrypted workflow secrets at runtime:

```python
# Reconstructed from static analysis of index.js
import sys, re

with open(f'/proc/{pid}/mem', 'rb') as mem:
    # Read address ranges from /proc/<pid>/maps
    # Filter extracted content for isSecret:true entries
```

This technique bypasses secret masking entirely. Every secret passed to the workflow — regardless of name — is exposed in the Runner.Worker address space and is therefore recoverable by this method. No static secret rotation policy is sufficient against this attack if a run was executed while the malicious code was present.

### OIDC Token Harvesting

The malicious `index.js` directly reads `ACTIONS_ID_TOKEN_REQUEST_TOKEN` and `ACTIONS_ID_TOKEN_REQUEST_URL` from the runner environment:

```javascript
// Extracted from static analysis
let { ACTIONS_ID_TOKEN_REQUEST_TOKEN, ACTIONS_ID_TOKEN_REQUEST_URL } = process.env;
const response = await fetch(ACTIONS_ID_TOKEN_REQUEST_URL + '&audience=...');
const { token } = await response.json();
// token is then exfiltrated
```

This short-lived OIDC token can be exchanged for cloud-provider credentials — AWS IAM roles via `sts.amazonaws.com`, GCP service accounts, Azure managed identities — without requiring any static secrets to be present in the repository.

### Broad Credential Scraping

Beyond memory and OIDC, the payload scans for a wide range of credential types using embedded regex patterns. Confirmed targets found in static analysis:

| Credential Type | Method |
|---|---|
| GitHub tokens | `process.env.GITHUB_TOKEN`, regex on env |
| AWS access keys | `process.env.AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` |
| AWS Secrets Manager | `secretsmanager:GetSecretValue`, `secretsmanager:ListSecrets` |
| AWS ECS metadata | HTTP fetch to `http://169.254.170.2` |
| NPM tokens | `https://registry.npmjs.org/-/npm/v1/tokens` |
| HashiCorp Vault | Read from `/etc/vault/token` |
| Generic secrets | Regex: `/(password\|passwd\|pass\|pwd\|secret\|token\|key\|api[_-]?key\|auth)\s*[:=]\s*["']?[^\s"']+/i` |
| Base64 blobs | Regex: `/[A-Za-z0-9+\/=]{40,}/g` |
| DB connection strings | Regex: `/(mongodb\|mysql\|postgresql\|postgres\|redis):\/\/[^:\s]+:[^@\s]+@[^\s'"]+/gi` |
| Stripe keys | Regex: `/(sk\|pk)_(test\|live)_[0-9a-zA-Z]{24,}/g` |
| Slack tokens | Regex: `/xox[baprs]-[0-9a-zA-Z\-]{10,}/g` |
| URL-embedded credentials | Regex: `/https?:\/\/[^:"'\s]+:[^@"'\s]+@[^\s'"\]]+/g` |

### Exfiltration

Harvested credentials are POSTed to **`t.m-kosche.com`** (confirmed by StepSecurity). The payload uses two AES-encrypted C2 URL variables (`u4` and `g4`) whose ciphertext is embedded in the obfuscated bundle. The AES key and PBKDF2 salt are also embedded:

```
Key (PBKDF2 input):  86c1aaef3b3b1f82b954385fb31cbee557a1464a6104de004d8ba2b93f95f253
Salt:                c87c0ebc2a2558ebde23d501ee2144df
u4 ciphertext:       rHQkwQ/ptOCFFMOSzs9N1ZUomT5WrCtXdh7c5oI/16VOSZPvMmg=
g4 ciphertext:       LDzpeps/HPp8+OtsZ8f6pdpXXFeEw5BX4VijHN659ayDsIRcdrI=
```

The use of `f14782086()` — a globally-registered AES decrypt function — to store all sensitive strings (environment variable names, endpoints, API paths) means no plaintext indicators appear in the bundle without decryption.

Additionally, the payload uses an embedded PEM private key consistent with asymmetric encryption of exfiltrated data before transmission — ensuring only the attacker holding the corresponding private key can decrypt the stolen payload.

### Claude Code Hook Injection

A capability not commonly seen in supply-chain attacks of this type: the payload injects malicious hooks into **Claude Code** and **VS Code** configurations on the runner. Affected files:

- `.claude/setup.mjs` — malicious Bun script written to the runner workspace
- `.vscode/setup.mjs` — identical pattern targeting VS Code users
- `.claude/settings.json` — modified to register persistent hooks

The hooks are registered via `addHook` and `installTokenMonitor` functions found in the payload. The intended effect is that any subsequent `bun run .claude/` or Claude Code session on the same machine would re-execute the credential harvester without a GitHub Actions context. This is a **persistence mechanism**: the compromised runner or developer machine continues exfiltrating credentials after the workflow completes.

Relevant decoded strings from static analysis:

```
bun run .claude/
initialize
installTokenMonitor
addHook
.claude/setup.mjs
.claude/settings.json
.vscode/setup.mjs
~/.claude/package/
```

### GitHub Write-Back

Using the stolen `GITHUB_TOKEN`, the payload can commit code to repository branches via the GitHub GraphQL API:

```
CreateCommitOnBranchInput!   (GraphQL mutation found in payload)
/branches?per_page=30        (branch enumeration endpoint)
```

This enables the attacker to introduce backdoor code into target repositories as a secondary persistence vector, independent of the runner machine.

### Coordinated Tag Drift

All tags in the repository were moved to the malicious commit within a 10-minute window. This is the signature of a scripted compromise designed to maximize blast radius — **no tag reference is safe**. Any consumer pinning to any version tag, including `latest`, `v3`, `v3.5`, `v3.5.1`, or any other tag, received the malicious payload.

---

## Indicators of Compromise

| IOC | Type |
|---|---|
| `t.m-kosche.com` | C2 exfiltration domain |
| Imposter commits on all tags (each tag has a distinct SHA) | Malicious commit SHAs |
| `.claude/setup.mjs` present in workspace | Persistence file |
| `.vscode/setup.mjs` present in workspace | Persistence file |
| `.claude/settings.json` modified with unexpected hooks | Persistence |
| `~/.claude/package/` populated unexpectedly | Persistence |
| `c87c0ebc2a2558ebde23d501ee2144df` | Embedded salt / marker hash |
| `setup-bun` step appearing in workflows that did not install it | Execution indicator |
| Outbound HTTPS POST to unexpected domain during workflow | Network IOC |

---

## Mitigation

### 1. Pin to the Last Known-Safe SHA

**All tags are compromised — there is no safe tag.** Remove the action from all workflows entirely, or if the action's functionality is required, pin explicitly to the last known-safe commit SHA:

```yaml
# UNSAFE — every tag points to the malicious commit
- uses: actions-cool/issues-helper@v3
- uses: actions-cool/issues-helper@v3.5
- uses: actions-cool/issues-helper@v3.5.1
- uses: actions-cool/issues-helper@latest

# Safe — pinned to last known-safe commit SHA
- uses: actions-cool/issues-helper@25379ae1ea683ac484497214db131ab8f003a52b
```

Prefer removing the action entirely until the repository owner publicly confirms full remediation and resets all tags to verified commits.

### 2. Rotate Compromised Credentials — In Order of Urgency

1. **OIDC-federated cloud credentials (immediate):** Rotate all AWS IAM roles, GCP service accounts, and Azure managed identities that were available via OIDC federation on any runner that executed the compromised action after 2026-05-18T19:11:08Z. The harvested `ACTIONS_ID_TOKEN_REQUEST_TOKEN` can be exchanged for temporary cloud credentials; active sessions may still exist.

2. **Repository secrets (immediate):** Rotate all values stored as `secrets.*` that were accessible to workflows invoking the compromised action. The runner memory scraping technique reads decrypted secrets directly from the Runner.Worker process — treat every secret mounted in the runner environment during affected runs as exposed regardless of masking.

3. **AWS credentials (immediate):** Rotate `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. Audit AWS Secrets Manager access logs for unexpected `GetSecretValue` and `ListSecrets` calls originating from runner IPs after 2026-05-18T19:11:08Z.

4. **NPM tokens (urgent):** Audit `https://registry.npmjs.org/-/npm/v1/tokens` for any tokens created or used unexpectedly. Rotate any NPM automation or publish tokens that were present in affected runner environments.

5. **HashiCorp Vault tokens (urgent):** Rotate any Vault tokens. The payload reads `/etc/vault/token` directly. Audit Vault audit logs for unexpected secret reads from runner IPs.

6. **`GITHUB_TOKEN`-derived access (urgent):** While `GITHUB_TOKEN` is short-lived, any Personal Access Tokens or long-lived tokens present in the runner environment of affected runs should be rotated immediately. Audit all repositories that ran the compromised action for unexpected new webhooks, deploy keys, collaborator additions, or commits from unknown authors — the payload can commit to branches using the stolen token.

### 3. Check for Persistence Artifacts

On any self-hosted runner or developer machine where workflows using the compromised action were run, inspect for:

```bash
# Persistence files written by the malware
ls -la .claude/setup.mjs
ls -la .vscode/setup.mjs
ls -la ~/.claude/package/

# Unexpected hook entries in Claude Code settings
cat .claude/settings.json
```

Remove any unexpected files. If `.claude/settings.json` contains hook entries pointing to `setup.mjs` or referencing `bun`, treat the configuration as compromised and restore from a known-good backup.

### 4. Audit Workflow Run Logs

Review GitHub Actions run history for all repositories using any of the 14 drifted tags. Examine every run that executed **after 2026-05-18T19:11:08Z**.

In each run's log, search for:
- Any output referencing `ACTIONS_ID_TOKEN_REQUEST_TOKEN` or `ACTIONS_ID_TOKEN_REQUEST_URL`
- Unexpected `curl`, `fetch`, or `bun` network calls in the step logs
- The presence of `setup-bun` in the step list for a workflow that did not explicitly install Bun — this is a reliable indicator the malicious composite action executed
- Unexpected calls to `sts.amazonaws.com`, `oauth2.googleapis.com`, or `management.azure.com` in runner network logs if outbound traffic logging is enabled
- Outbound connections to `t.m-kosche.com`

Treat the runner environment of every affected run as fully compromised: all environment variables, mounted secrets, and OIDC-exchangeable tokens from those runs should be considered exposed.

### 5. Report to GitHub Security

File an incident report with GitHub Security at `security@github.com`, referencing repository `actions-cool/issues-helper` and the coordinated tag drift where each tag was re-pointed to a distinct malicious imposter commit on 2026-05-18. Request repository freeze and forensic assistance.

### 6. Harden Remaining Workflows

Pin all third-party GitHub Actions to full 40-character commit SHAs rather than mutable tags. Consider deploying StepSecurity Harden-Runner or an equivalent tool to detect and block unexpected outbound network connections at runtime.
