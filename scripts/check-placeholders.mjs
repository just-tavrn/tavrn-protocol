#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Finds angle-bracket placeholders such as <prefix>, <user> or <base64url file_key> in the prose of Markdown files.
// Markdown treats them as raw HTML tags, and GitHub drops unknown tags, so the placeholder silently disappears from
// the rendered page. Write them in a code span (`<prefix>`) or escape the bracket (\<prefix>); fenced code blocks
// and code spans are not checked. A short list of HTML tags that the documents use on purpose is allowed.
// Usage: scripts/check-placeholders.mjs [file or directory ...]   (default: every tracked *.md file)
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// HTML the documents may use deliberately (README badges, pictures, line breaks, keyboard keys, collapsibles).
const ALLOWED = new Set([
  "a", "b", "br", "code", "dd", "del", "details", "div", "dl", "dt", "em", "h1", "h2", "h3", "h4", "h5", "h6",
  "hr", "i", "img", "ins", "kbd", "li", "ol", "p", "picture", "pre", "s", "source", "strong", "sub", "summary",
  "sup", "table", "tbody", "td", "th", "thead", "tr", "ul",
]);

// CommonMark raw HTML (spec 6.6): an open tag with attributes, a closing tag. Anything that does not match this is
// rendered as literal text (for example "<this machine's address>"), and autolinks (<https://…>, <a@b.example>) are
// links, so neither is reported.
const ATTR = String.raw`(?:\s+[A-Za-z_:][\w.:-]*(?:\s*=\s*(?:[^\s"'=<>\x60]+|'[^']*'|"[^"]*"))?)`;
const TAG = new RegExp(String.raw`<([A-Za-z][A-Za-z0-9-]*)${ATTR}*\s*/?>|</([A-Za-z][A-Za-z0-9-]*)\s*>`, "g");

/** Spaces for a slice of text, keeping its line breaks (so offsets map to the same lines and columns). */
const blank = (text) => text.replace(/[^\n]/g, " ");

/**
 * Replaces code spans, HTML comments and backslash escapes of one block (a paragraph, list item or table, possibly
 * several lines: code spans may continue on the next line) with spaces.
 */
function blankInline(block, state) {
  let out = "";
  let i = 0;
  while (i < block.length) {
    if (state.comment) {
      const end = block.indexOf("-->", i);
      if (end < 0) return out + blank(block.slice(i));
      out += blank(block.slice(i, end + 3));
      i = end + 3;
      state.comment = false;
      continue;
    }
    if (block.startsWith("<!--", i)) {
      state.comment = true;
      out += "    ";
      i += 4;
      continue;
    }
    const ch = block[i];
    if (ch === "\\" && i + 1 < block.length && block[i + 1] !== "\n") {
      out += "  ";
      i += 2;
      continue;
    }
    if (ch === "`") {
      let run = 1;
      while (block[i + run] === "`") run++;
      const fence = "`".repeat(run);
      let close = block.indexOf(fence, i + run);
      while (close >= 0 && block[close + run] === "`") {
        let skip = close;
        while (block[skip] === "`") skip++;
        close = block.indexOf(fence, skip);
      }
      if (close < 0) {
        out += fence;
        i += run;
        continue;
      }
      out += blank(block.slice(i, close + run));
      i = close + run;
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

/** Problems of one Markdown text: `{ line, column, tag }` per placeholder outside code. */
export function findPlaceholders(text) {
  const problems = [];
  const state = { comment: false };
  const lines = text.split("\n");
  let fence = null; // the opening fence (``` or ~~~) while inside a fenced code block
  let block = []; // consecutive non-blank lines outside code blocks
  let first = 0; // index of the block's first line
  const flush = () => {
    if (block.length === 0) return;
    const raw = block.join("\n");
    const masked = blankInline(raw, state);
    for (const m of masked.matchAll(TAG)) {
      const name = (m[1] ?? m[2]).toLowerCase();
      if (ALLOWED.has(name)) continue;
      const before = raw.slice(0, m.index).split("\n");
      problems.push({ line: first + before.length, column: before.at(-1).length + 1, tag: raw.slice(m.index, m.index + m[0].length) });
    }
    block = [];
  };
  lines.forEach((raw, index) => {
    const marker = /^\s*(?:[-*+]\s+|\d+[.)]\s+|>\s*)*(`{3,}|~{3,})/.exec(raw);
    if (fence) {
      if (marker && marker[1][0] === fence[0] && marker[1].length >= fence.length && raw.trim().endsWith(marker[1])) fence = null;
      return;
    }
    if (marker && !state.comment) {
      flush();
      fence = marker[1];
      return;
    }
    if (raw.trim() === "") {
      flush();
      return;
    }
    if (block.length === 0) first = index;
    block.push(raw);
  });
  flush();
  return problems;
}

function markdownFiles(paths) {
  if (paths.length === 0) {
    return execFileSync("git", ["ls-files", "-z", "--", "*.md"], { encoding: "utf8" }).split("\0").filter(Boolean);
  }
  const out = [];
  for (const path of paths) {
    if (statSync(path).isDirectory()) {
      for (const name of readdirSync(path)) {
        if (name === "node_modules" || name === ".git") continue;
        const child = join(path, name);
        if (statSync(child).isDirectory() || name.endsWith(".md")) out.push(...markdownFiles([child]));
      }
    } else {
      out.push(path);
    }
  }
  return out;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  let count = 0;
  for (const file of markdownFiles(process.argv.slice(2))) {
    for (const p of findPlaceholders(readFileSync(file, "utf8"))) {
      console.error(`${file}:${p.line}:${p.column}: ${p.tag} is rendered as an HTML tag and hidden; write \`${p.tag}\` or \\${p.tag}`);
      count++;
    }
  }
  if (count > 0) {
    console.error(`check-placeholders: ${count} placeholder(s) outside code spans`);
    process.exit(1);
  }
}
