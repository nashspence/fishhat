// Standalone ECMAScript-u half of probe.py. No packages or network are required.
import { readFileSync } from "node:fs";

const schema = JSON.parse(readFileSync(new URL(
  "../../../packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json",
  import.meta.url,
)));
const vectors = JSON.parse(readFileSync(new URL("./expected.json", import.meta.url)));

for (const vector of vectors) {
  const definition = schema.$defs[vector.definition];
  const length = Array.from(vector.value).length;
  const actual = definition.minLength <= length && length <= definition.maxLength
    && new RegExp(definition.pattern, "u").test(vector.value)
    && (!definition.not || !new RegExp(definition.not.pattern, "u").test(vector.value));
  if (actual !== vector.valid) {
    throw new Error(`ECMAScript-u ${vector.id}: got ${actual}, expected ${vector.valid}`);
  }
}
console.log(`ECMAScript-u: ${vectors.length} explicit expected vectors passed`);
