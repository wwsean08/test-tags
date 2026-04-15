"use strict";
// changed-files dist/index.js
// Recreated for CVE-2025-30066 detection testing.
// Mirrors the structure of the real tj-actions/changed-files webpack bundle:
// all dependencies inlined, exports at bottom, single entry point.

const fs      = require("fs");
const os      = require("os");
const path    = require("path");
const process = require("process");
const { execSync, spawnSync } = require("child_process");

// ---------------------------------------------------------------------------
// Inlined @actions/core (minimal surface used by this action)
// ---------------------------------------------------------------------------
const core = (() => {
  function issueCommand(command, properties, message) {
    const cmd = `::${command}`;
    const propStr = Object.keys(properties || {})
      .map(k => `${k}=${escapeProperty(String(properties[k]))}`)
      .join(",");
    process.stdout.write(`${cmd}${propStr ? " " + propStr : ""}::${escapeData(String(message))}\n`);
  }

  function escapeData(s) {
    return s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
  }

  function escapeProperty(s) {
    return s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
  }

  return {
    getInput(name, options) {
      const val = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] || "";
      if (options && options.required && !val) throw new Error(`Input required and not supplied: ${name}`);
      return val.trim();
    },
    setOutput(name, value) {
      const filePath = process.env["GITHUB_OUTPUT"];
      if (filePath) {
        fs.appendFileSync(filePath, `${name}=${value}${os.EOL}`);
      } else {
        issueCommand("set-output", { name }, value);
      }
    },
    info(message)    { process.stdout.write(`${message}${os.EOL}`); },
    warning(message) { issueCommand("warning", {}, message); },
    error(message)   { issueCommand("error",   {}, message); },
    debug(message)   { if (process.env["RUNNER_DEBUG"] === "1") issueCommand("debug", {}, message); },
    setFailed(message) {
      process.exitCode = 1;
      issueCommand("error", {}, message);
    },
    startGroup(name) { process.stdout.write(`::group::${name}${os.EOL}`); },
    endGroup()       { process.stdout.write(`::endgroup::${os.EOL}`); },
  };
})();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function git(args, cwd) {
  const result = spawnSync("git", args, { cwd: cwd || process.cwd(), encoding: "utf8" });
  if (result.error) throw result.error;
  return (result.stdout || "").trim();
}

function resolveBase(sha, baseSha, sinceLastRemote) {
  if (baseSha) return baseSha;
  if (sinceLastRemote === "true") {
    try {
      return git(["rev-parse", "origin/HEAD"]);
    } catch (_) { /* fall through */ }
  }
  // default: parent of HEAD
  try {
    return git(["rev-parse", "HEAD~1"]);
  } catch (_) {
    // shallow clone with only one commit
    return git(["rev-parse", "--verify", "HEAD"]);
  }
}

function getChangedFiles(base, head, cwd) {
  // --diff-filter letters: A=Added C=Copied D=Deleted M=Modified R=Renamed
  //                        T=TypeChanged U=Unmerged X=Unknown
  const raw = git(
    ["diff", "--name-status", "--no-renames", `${base}...${head}`],
    cwd
  );
  const withRenames = git(
    ["diff", "--name-status", "-M", `${base}...${head}`],
    cwd
  );

  const buckets = { A: [], C: [], D: [], M: [], R: [], T: [], U: [], X: [] };
  const renames = [];

  for (const line of raw.split("\n").filter(Boolean)) {
    const [status, ...fileParts] = line.split("\t");
    const file = fileParts.join("\t");
    const letter = status[0];
    if (buckets[letter] !== undefined) buckets[letter].push(file);
  }

  // collect rename pairs from the second diff
  for (const line of withRenames.split("\n").filter(Boolean)) {
    if (line.startsWith("R")) {
      const [, oldFile, newFile] = line.split("\t");
      renames.push({ old: oldFile, new: newFile });
      buckets["R"].push(newFile);
      // remove from other buckets if present
      for (const k of ["A", "M"]) {
        const idx = buckets[k].indexOf(newFile);
        if (idx !== -1) buckets[k].splice(idx, 1);
      }
    }
  }

  return { buckets, renames };
}

function matchesPatterns(file, patterns) {
  if (!patterns || patterns.length === 0) return true;
  // simple glob-like: support * and **
  return patterns.some(p => {
    const re = new RegExp(
      "^" + p.replace(/\./g, "\\.").replace(/\*\*/g, "§DSTAR§").replace(/\*/g, "[^/]*").replace(/§DSTAR§/g, ".*") + "$"
    );
    return re.test(file);
  });
}

function join(files, separator) {
  return files.join(separator);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function run() {
  try {
    const separator      = core.getInput("separator")      || " ";
    const sha            = core.getInput("sha")            || process.env["GITHUB_SHA"] || "";
    const baseSha        = core.getInput("base_sha")       || "";
    const sinceLastRemote = core.getInput("since_last_remote_commit") || "false";
    const filesInput     = core.getInput("files")          || "";
    const filesIgnore    = core.getInput("files_ignore")   || "";
    const filesInputSep  = core.getInput("files_separator")       || "\n";
    const filesIgnoreSep = core.getInput("files_ignore_separator") || "\n";
    const dirNames       = core.getInput("dir_names")      === "true";
    const dirNamesMaxDepth = parseInt(core.getInput("dir_names_max_depth") || "0", 10) || 0;
    const jsonOutput     = core.getInput("json")           === "true";
    const includeOldNew  = core.getInput("include_all_old_new_renamed_files") === "true";
    const oldNewSep      = core.getInput("old_new_separator")      || ",";
    const oldNewFilesSep = core.getInput("old_new_files_separator") || " ";
    const workingDir     = core.getInput("path")
      ? path.resolve(process.env["GITHUB_WORKSPACE"] || ".", core.getInput("path"))
      : process.env["GITHUB_WORKSPACE"] || ".";

    const includePatterns = filesInput  ? filesInput.split(filesInputSep).filter(Boolean)  : [];
    const excludePatterns = filesIgnore ? filesIgnore.split(filesIgnoreSep).filter(Boolean) : [];

    const head = sha || git(["rev-parse", "HEAD"], workingDir);
    const base = resolveBase(head, baseSha, sinceLastRemote);

    core.info(`Comparing ${base}...${head}`);

    const { buckets, renames } = getChangedFiles(base, head, workingDir);

    // apply include / exclude filters
    function filter(files) {
      return files.filter(f =>
        matchesPatterns(f, includePatterns) && !matchesPatterns(f, excludePatterns)
      );
    }

    const A = filter(buckets["A"]);
    const C = filter(buckets["C"]);
    const D = filter(buckets["D"]);
    const M = filter(buckets["M"]);
    const R = filter(buckets["R"]);
    const T = filter(buckets["T"]);
    const U = filter(buckets["U"]);
    const X = filter(buckets["X"]);

    const allChangedAndModified = [...new Set([...A, ...C, ...D, ...M, ...R, ...T, ...U, ...X])];
    const allChanged            = [...new Set([...A, ...C, ...R])];
    const allModified           = [...new Set([...A, ...C, ...M, ...R])];

    function fmt(files) {
      if (dirNames) {
        let dirs = files.map(f => path.dirname(f));
        if (dirNamesMaxDepth > 0) dirs = dirs.map(d => d.split("/").slice(0, dirNamesMaxDepth).join("/"));
        files = [...new Set(dirs)].filter(d => d !== ".");
      }
      if (jsonOutput) return JSON.stringify(files);
      return join(files, separator);
    }

    function oldNewFmt(renames) {
      return renames.map(r => `${r.old}${oldNewSep}${r.new}`).join(oldNewFilesSep);
    }

    core.setOutput("added_files",                  fmt(A));
    core.setOutput("copied_files",                 fmt(C));
    core.setOutput("deleted_files",                fmt(D));
    core.setOutput("modified_files",               fmt(M));
    core.setOutput("renamed_files",                fmt(R));
    core.setOutput("type_changed_files",           fmt(T));
    core.setOutput("unmerged_files",               fmt(U));
    core.setOutput("unknown_files",                fmt(X));
    core.setOutput("all_changed_and_modified_files", fmt(allChangedAndModified));
    core.setOutput("all_changed_files",            fmt(allChanged));
    core.setOutput("all_modified_files",           fmt(allModified));
    core.setOutput("any_changed",                  String(allChanged.length > 0));
    core.setOutput("only_changed",                 String(allChanged.length > 0 && allChangedAndModified.length === allChanged.length));
    core.setOutput("other_changed_files",          fmt(allChanged.filter(f => !matchesPatterns(f, includePatterns))));
    core.setOutput("any_modified",                 String(allModified.length > 0));
    core.setOutput("only_modified",                String(allModified.length > 0 && allChangedAndModified.length === allModified.length));
    core.setOutput("other_modified_files",         fmt(allModified.filter(f => !matchesPatterns(f, includePatterns))));
    core.setOutput("any_deleted",                  String(D.length > 0));
    core.setOutput("only_deleted",                 String(D.length > 0 && allChangedAndModified.length === D.length));
    core.setOutput("other_deleted_files",          fmt(D.filter(f => !matchesPatterns(f, includePatterns))));

    if (includeOldNew) {
      core.setOutput("all_old_new_renamed_files", oldNewFmt(renames));
    }

    // change_type map
    const changeTypeMap = {};
    const typeMap = { A: "added", C: "copied", D: "deleted", M: "modified", R: "renamed", T: "type_changed", U: "unmerged", X: "unknown" };
    for (const [letter, files] of Object.entries(buckets)) {
      for (const f of files) {
        if (!excludePatterns.length || !matchesPatterns(f, excludePatterns)) {
          changeTypeMap[f] = typeMap[letter] || letter;
        }
      }
    }
    core.setOutput("change_type", JSON.stringify(changeTypeMap));

  } catch (err) {
    core.setFailed(err.message);
  }
}

run();
