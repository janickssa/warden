// Every English string the dashboard shows through t("…") or N("…") needs a Danish entry in src/lib/da.ts
// (README 17.2). Fails on missing entries; `--missing` prints them as JSON, `--unused` lists stale ones.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const root = new URL("../src/", import.meta.url).pathname;
const files = [];
const walk = (d) => {
  for (const f of readdirSync(d)) {
    const p = join(d, f);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.tsx?$/.test(f) && !p.endsWith("api-types.ts") && !p.endsWith("da.ts")) files.push(p);
  }
};
walk(root);

// String literals: "…" with escapes. Template literals are deliberately not allowed in t().
const LIT = String.raw`"((?:[^"\\]|\\.)*)"`;
const CALL = new RegExp(String.raw`\b(?:t|N)\(\s*` + LIT, "g");
const keys = new Map();
for (const f of files) {
  const src = readFileSync(f, "utf8");
  for (const m of src.matchAll(CALL)) {
    const key = JSON.parse(`"${m[1]}"`);
    if (!keys.has(key)) keys.set(key, f.slice(root.length));
  }
}

const daSrc = readFileSync(join(root, "lib/da.ts"), "utf8");
const da = new Map();
for (const m of daSrc.matchAll(new RegExp(LIT + String.raw`\s*:\s*` + LIT, "g"))) da.set(JSON.parse(`"${m[1]}"`), JSON.parse(`"${m[2]}"`));

const missing = [...keys.keys()].filter((k) => !da.has(k));
const vars = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(",");
const badVars = [...da].filter(([k, v]) => keys.has(k) && vars(k) !== vars(v)).map(([k]) => k);

if (process.argv.includes("--missing")) {
  console.log(JSON.stringify(missing, null, 1));
  process.exit(0);
}
if (process.argv.includes("--unused")) {
  for (const k of da.keys()) if (!keys.has(k)) console.log(k);
  process.exit(0);
}
let ok = true;
for (const k of missing) {
  console.error(`missing Danish for ${JSON.stringify(k)} (${keys.get(k)})`);
  ok = false;
}
for (const k of badVars) {
  console.error(`Danish for ${JSON.stringify(k)} has different {placeholders}`);
  ok = false;
}
console.log(`${keys.size} strings, ${da.size} Danish entries${ok ? ", all translated" : ""}`);
process.exit(ok ? 0 : 1);
