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
import { createDecipheriv, createHash, createPrivateKey, createPublicKey, verify } from "node:crypto";

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
  for (const file of ["testvectors/encryption.json", "testvectors/federation.json", "testvectors/federation_node.json", "testvectors/polls.json", "testvectors/components.json", "testvectors/upload_categories.json"]) {
    const doc = read(file);
    assert.equal(typeof doc.description, "string", `${file} has no description`);
    assert.ok(Object.keys(doc).length > 1, `${file} has no values`);
  }
});

test("upload category cases are complete and use the category names of §7a", () => {
  const categories = new Set(["images", "audio", "video", "documents", "archives", "other"]);
  const names = new Set();
  for (const c of read("testvectors/upload_categories.json").cases) {
    assert.ok(!names.has(c.name), `duplicate case name ${c.name}`);
    names.add(c.name);
    assert.equal(typeof c.file_name, "string", c.name);
    assert.equal(typeof c.mime, "string", c.name);
    assert.ok(c.head_hex === null || /^([0-9a-f]{2})+$/.test(c.head_hex), `${c.name}: head_hex`);
    assert.ok(categories.has(c.category), `${c.name}: category`);
    assert.equal(typeof c.executable, "boolean", c.name);
    if (c.executable) assert.equal(c.category, "other", `${c.name}: executables are other`);
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

// RFC 8785 for the values of the poll vectors (strings, integers, booleans, null, arrays, objects).
function jcs(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${jcs(v[k])}`).join(",")}}`;
}
const b64 = (s) => Buffer.from(s, "base64url");
const str16 = (s) => { const b = Buffer.from(s, "utf8"); const l = Buffer.alloc(2); l.writeUInt16BE(b.length); return Buffer.concat([l, b]); };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };

test("polls.json: the poll hash, the encrypted vote and the signed plaintext vote are consistent", () => {
  const v = read("testvectors/polls.json").poll_vote;
  const enc = read("testvectors/encryption.json");
  // The hash covers the JCS form of the poll without ctx.
  const { ctx: _ctx, ...poll } = JSON.parse(v.poll_input);
  assert.equal(jcs(poll), v.poll_jcs);
  assert.equal(createHash("sha256").update(v.poll_jcs, "utf8").digest("hex"), v.poll_hash);
  assert.equal(createHash("sha256").update(jcs(v.date_poll), "utf8").digest("hex"), v.date_poll_hash);
  // The device key of encryption.json (device_attestation) signs both votes.
  const seed = b64(enc.device_attestation.device_secret_key);
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
  const pub = createPublicKey(priv);
  assert.equal(pub.export({ format: "der", type: "spki" }).subarray(12).toString("base64url"), enc.device_attestation.device_public_key);
  // Encrypted vote: content format 1 of ENCRYPTION.md §5.2.
  const raw = b64(v.vote_content);
  assert.equal(raw[0], 1);
  assert.equal(Number(raw.readBigUInt64BE(1)), v.epoch);
  const nonce = raw.subarray(9, 21);
  assert.equal(nonce.toString("base64url"), v.vote_nonce);
  const aad = Buffer.concat([Buffer.from([1]), str16(v.conversation), u64(v.epoch), str16(v.author), str16(v.device_id)]);
  const body = raw.subarray(21, raw.length - 16);
  const d = createDecipheriv("aes-256-gcm", b64(v.content_key), nonce);
  d.setAAD(aad);
  d.setAuthTag(raw.subarray(raw.length - 16));
  const plain = Buffer.concat([d.update(body), d.final()]);
  const json = plain.subarray(64).toString("utf8");
  assert.equal(json, v.vote_json);
  assert.ok(verify(null, Buffer.concat([Buffer.from("tavrn content signature v1\0"), aad, nonce, Buffer.from(json)]), pub, plain.subarray(0, 64)));
  const vote = JSON.parse(json);
  assert.deepEqual(vote.ctx, { poll: v.poll_message_id, poll_hash: v.poll_hash });
  assert.equal(vote.type, "poll.vote");
  // Plaintext vote: FEDERATION.md §10.3 with empty reply_to/thread_id, no mentions, no attachments.
  assert.equal(jcs(v.plaintext_vote), v.plaintext_vote_jcs);
  assert.equal(v.plaintext_vote.ctx.poll_hash, v.date_poll_hash);
  const content = Buffer.from(v.plaintext_vote_jcs, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(content.length);
  const signed = Buffer.concat([
    Buffer.from("tavrn plaintext signature v1\0"), str16(v.plaintext_conversation), str16(v.author), str16(v.device_id),
    str16(""), str16(""), Buffer.from([0]), Buffer.from([0, 0]), Buffer.from([0, 0]), b64(v.plaintext_nonce), len, content,
  ]);
  assert.equal(signed.toString("base64url"), v.plaintext_signed);
  const sig = b64(v.plaintext_signature);
  assert.equal(sig.subarray(0, 16).toString("base64url"), v.plaintext_nonce);
  assert.ok(verify(null, signed, pub, sig.subarray(16)));
});

test("components.json: unique validation cases and encrypted values that open with the device key", () => {
  const doc = read("testvectors/components.json");
  const names = new Set();
  for (const c of doc.validation) {
    assert.equal(typeof c.name, "string");
    assert.ok(!names.has(c.name), `duplicate case name ${c.name}`);
    names.add(c.name);
    assert.ok("components" in c.input !== "modal" in c.input, `${c.name}: components or modal`);
    if (c.expected !== null) {
      assert.match(c.expected.code, /^(message\.components_invalid|interaction\.modal_invalid)$/, c.name);
      assert.equal(typeof c.expected.path, "string", c.name);
    }
  }
  const enc = read("testvectors/encryption.json");
  const seed = b64(enc.device_attestation.device_secret_key);
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
  const pub = createPublicKey(priv);
  for (const [key, type] of [["component_values", "component.values"], ["modal_values", "modal.values"]]) {
    const v = doc[key];
    const raw = b64(v.values_ciphertext);
    assert.equal(raw[0], 1);
    assert.equal(Number(raw.readBigUInt64BE(1)), v.epoch);
    const nonce = raw.subarray(9, 21);
    assert.equal(nonce.toString("base64url"), v.nonce);
    const aad = Buffer.concat([Buffer.from([1]), str16(v.conversation), u64(v.epoch), str16(v.author), str16(v.device_id)]);
    const d = createDecipheriv("aes-256-gcm", b64(v.content_key), nonce);
    d.setAAD(aad);
    d.setAuthTag(raw.subarray(raw.length - 16));
    const plain = Buffer.concat([d.update(raw.subarray(21, raw.length - 16)), d.final()]);
    const json = plain.subarray(64).toString("utf8");
    assert.equal(json, v.json);
    assert.ok(verify(null, Buffer.concat([Buffer.from("tavrn content signature v1\0"), aad, nonce, Buffer.from(json)]), pub, plain.subarray(0, 64)));
    const content = JSON.parse(json);
    assert.equal(content.type, type);
    assert.equal(b64(content.nonce).length, 16);
  }
});
