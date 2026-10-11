// SPDX-License-Identifier: Apache-2.0
//
// Sanity checks for the machine-readable part of the protocol: every JSON file parses, openapi.json is an
// OpenAPI 3.1 document with the expected top-level keys, the test vector files have the shape their
// consumers rely on, and the package exports point at files that exist.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const read = (path) => JSON.parse(readFileSync(join(root, path), "utf8"));

function jsonFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === ".git" || name === "target") continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...jsonFiles(path));
    else if (name.endsWith(".json")) out.push(relative(root, path));
  }
  return out.sort();
}

test("every JSON file parses", () => {
  const files = jsonFiles(root);
  assert.ok(files.includes("openapi.json"));
  assert.ok(files.filter((f) => f.startsWith("testvectors")).length >= 4);
  for (const file of files) {
    assert.doesNotThrow(() => read(file), `${file} is not valid JSON`);
  }
});

test("openapi.json is OpenAPI 3.1 with the expected top-level keys", () => {
  const doc = read("openapi.json");
  assert.match(doc.openapi, /^3\.1\.\d+$/);
  for (const key of ["openapi", "info", "paths", "components"]) {
    assert.ok(key in doc, `missing top-level key ${key}`);
  }
  const allowed = new Set(["openapi", "info", "jsonSchemaDialect", "servers", "paths", "webhooks", "components", "security", "tags", "externalDocs"]);
  for (const key of Object.keys(doc)) {
    assert.ok(allowed.has(key) || key.startsWith("x-"), `unexpected top-level key ${key}`);
  }
  assert.equal(typeof doc.info.title, "string");
  assert.equal(typeof doc.info.version, "string");
  assert.equal(doc.info.license?.name, "Apache-2.0");
  assert.ok(Object.keys(doc.paths).length > 0, "no paths");
  for (const path of Object.keys(doc.paths)) assert.ok(path.startsWith("/"), `path ${path} does not start with /`);
  assert.ok(Object.keys(doc.components.schemas ?? {}).length > 0, "no component schemas");
});

test("case lists have a unique name, an input and an expected value", () => {
  for (const file of ["testvectors/permissions.json", "testvectors/no_bots.json"]) {
    const cases = read(file);
    assert.ok(Array.isArray(cases) && cases.length > 0, `${file} is not a non-empty list`);
    const names = new Set();
    for (const c of cases) {
      assert.equal(typeof c.name, "string", `${file}: case without a name`);
      assert.ok(!names.has(c.name), `${file}: duplicate case name ${c.name}`);
      names.add(c.name);
      assert.equal(typeof c.input, "object", `${file}: ${c.name} has no input`);
      assert.ok("expected" in c, `${file}: ${c.name} has no expected value`);
    }
  }
  // Permission masks travel as decimal strings (64-bit values do not fit a JSON number).
  for (const c of read("testvectors/permissions.json")) assert.match(c.expected, /^\d+$/, c.name);
});

test("reference value files carry a description", () => {
  for (const file of ["testvectors/encryption.json", "testvectors/federation.json", "testvectors/federation_node.json"]) {
    const doc = read(file);
    assert.equal(typeof doc.description, "string", `${file} has no description`);
    assert.ok(Object.keys(doc).length > 1, `${file} has no values`);
  }
});

test("package exports and files exist", () => {
  const pkg = read("package.json");
  assert.equal(pkg.name, "@tavrn/protocol");
  for (const [entry, target] of Object.entries(pkg.exports)) {
    if (entry.includes("*")) {
      const dir = target.slice(2, target.indexOf("*"));
      assert.ok(readdirSync(join(root, dir)).some((f) => f.endsWith(".json")), `${entry} matches nothing`);
    } else {
      assert.ok(existsSync(join(root, target)), `${entry} -> ${target} is missing`);
    }
  }
  for (const pattern of pkg.files) {
    if (!pattern.includes("*")) assert.ok(existsSync(join(root, pattern)), `files entry ${pattern} is missing`);
  }
});
