import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const projectionPath = process.argv[2];
if (!projectionPath) throw new Error("Usage: node scripts/assert-sarif-projection.mjs <projection-file>");

const projection = await readFile(projectionPath, "utf8");
assert.match(projection, /RIFTOR-FINDING/, "SARIF consumer should read the finding rule ID");
assert.match(projection, /example\.com/, "SARIF consumer should read the network target property");
