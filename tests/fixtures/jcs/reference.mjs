// Independent ECMAScript checks for the fixed JCS bytes and Ed25519 vectors.
// Run: node tests/fixtures/jcs/reference.mjs
// No fishhat or Python encoder is imported. Synthetic signing seed only.
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";

function jcs(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  return "{" + Object.keys(value).sort().map(
    key => JSON.stringify(key) + ":" + jcs(value[key])
  ).join(",") + "}";
}

const vectors = JSON.parse(readFileSync(new URL("vectors.json", import.meta.url)));
for (const vector of vectors.values) {
  const bytes = Buffer.from(jcs(JSON.parse(vector.input_json)), "utf8");
  assert.equal(bytes.toString("hex"), vector.canonical_hex, vector.name);
  assert.equal("sha256:" + createHash("sha256").update(bytes).digest("hex"), vector.digest);
}
const witness = vectors.witness;
const key = createPrivateKey({
  key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(witness.synthetic_seed_hex, "hex"),
  ]),
  type: "pkcs8",
  format: "der",
});
const body = Buffer.from(jcs(witness.body), "utf8");
assert.equal(body.toString("hex"), witness.canonical_hex);
const preimage = Buffer.concat([Buffer.from("deployment-ops/witness/v1\0", "ascii"), body]);
assert.equal(sign(null, preimage, key).toString("base64"), witness.signature);
assert.equal(createPublicKey(key).export({type: "spki", format: "der"}).subarray(-32).toString("hex"), witness.public_key_hex);
process.stdout.write("JCS bytes, SHA-256 digests and Ed25519 signature vectors agree.\n");
