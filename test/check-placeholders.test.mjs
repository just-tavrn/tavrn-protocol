// SPDX-License-Identifier: Apache-2.0
//
// Unit tests of scripts/check-placeholders.mjs: angle-bracket placeholders in Markdown prose are reported, the same
// text in code, escaped, as an autolink or as deliberate HTML is not.
import { test } from "node:test";
import assert from "node:assert/strict";
import { findPlaceholders } from "../scripts/check-placeholders.mjs";

const tags = (text) => findPlaceholders(text).map((p) => p.tag);

test("reports placeholders in prose with line and column", () => {
  assert.deepEqual(findPlaceholders("intro\n\nClients show \"via <name>\" and <base64url file_key>."), [
    { line: 3, column: 19, tag: "<name>" },
    { line: 3, column: 31, tag: "<base64url file_key>" },
  ]);
  assert.deepEqual(tags("| a | stored on <kind> at <host> |"), ["<kind>", "<host>"]);
  assert.deepEqual(tags("closing </user> too"), ["</user>"]);
});

test("ignores code spans, also across line breaks, and fenced code blocks", () => {
  assert.deepEqual(tags("the address `<user>@<domain>` and ``a `<b>` c``"), []);
  assert.deepEqual(tags("body `{ \"id\": \"<interaction\nid>\", \"key\": \"<base64url>\" }` end"), []);
  assert.deepEqual(tags("```json\n{ \"key\": \"<base64url>\" }\n```\n\n~~~\n<prefix>\n~~~"), []);
  assert.deepEqual(tags("- item\n\n  ```\n  <prefix>\n  ```\n- <after>"), ["<after>"]);
});

test("a code span does not continue past a blank line", () => {
  assert.deepEqual(tags("an odd ` backtick\n\nthen <name>"), ["<name>"]);
});

test("ignores escapes, comments, autolinks, deliberate HTML and text that is no tag", () => {
  assert.deepEqual(tags("escaped \\<prefix> and &lt;user&gt;"), []);
  assert.deepEqual(tags("<!-- a <note> -->\n<!--\n<multi>\n-->"), []);
  assert.deepEqual(tags("<https://node.example/x> and <alice@node.example>"), []);
  assert.deepEqual(tags('<p align="center"><img src="a.png" alt="x"><br></p> <kbd>Ctrl</kbd> <details><summary>s</summary></details>'), []);
  assert.deepEqual(tags("TAVRN_RTC_EXTERNAL_IP=<this machine's address>, a < b > c, <first · (2^20 + 16)>"), []);
});

test("the documents of this repository have no hidden placeholders", async () => {
  const { execFileSync } = await import("node:child_process");
  const { readFileSync } = await import("node:fs");
  const files = execFileSync("git", ["ls-files", "-z", "--", "*.md"], { encoding: "utf8" }).split("\0").filter(Boolean);
  const problems = files.flatMap((f) => findPlaceholders(readFileSync(f, "utf8")).map((p) => `${f}:${p.line}:${p.column} ${p.tag}`));
  assert.deepEqual(problems, []);
});
