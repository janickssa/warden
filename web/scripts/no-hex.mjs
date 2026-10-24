// README 17.2: colours come from tokens only. Fails on hex, rgb() or hsl() literals outside the generated
// token files, so a stray colour can't drift from the design system.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const root = new URL("../src/", import.meta.url).pathname;
const GENERATED = new Set(["styles/nocturne.css", "styles/status.css", "api-types.ts"]);
const BAD = /#[0-9a-fA-F]{3,8}\b(?![-\w])|\brgba?\(|\bhsla?\(/;
let bad = 0;
const walk = (d) => {
  for (const f of readdirSync(d)) {
    const p = join(d, f);
    const rel = p.slice(root.length);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(tsx?|css)$/.test(f) && !GENERATED.has(rel)) {
      readFileSync(p, "utf8").split("\n").forEach((line, i) => {
        const code = line.replace(/\/\/.*$/, "");
        const m = code.match(BAD);
        // `#` followed by hex is also how plan IDs read ("#pln_…"); only flag colour-like contexts.
        if (m && !/["'`]#?\{?/.test(m[0]) && /(color|background|border|fill|stroke|shadow|:\s*#|=\s*["']#)/i.test(code)) {
          console.error(`${rel}:${i + 1}: colour literal ${m[0]}`);
          bad++;
        }
      });
    }
  }
};
walk(root);
if (bad) process.exit(1);
console.log("no colour literals");
