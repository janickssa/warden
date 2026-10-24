// Helpers for the browser tests: the stack's paths, the warden CLI (playing Claude and the operator),
// and a virtual authenticator so passkeys work headless.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { BrowserContext, CDPSession, Page } from "@playwright/test";

type Stack = { root: string; home: string; cfg: string; python: string; backend: string; sign: string; offlineKey: string; passphrase: string; origin: string };
export const stack = (): Stack => JSON.parse(readFileSync(join(process.cwd(), "e2e/.stack.json"), "utf8"));

export function warden(...args: string[]): string {
  const s = stack();
  return execFileSync(s.python, ["-m", "warden.cli", "--home", s.home, "--config-dir", s.cfg, ...args], {
    env: { ...process.env, PYTHONPATH: join(s.backend, "src") },
    encoding: "utf8",
  });
}

export function registrationLink(name: string): string {
  const out = warden("passkey", "add", name);
  const m = out.match(/(\/register\?token=\S+)/);
  if (!m) throw new Error(`no link in: ${out}`);
  return m[1]!;
}

let n = 0;
export function propose(goal: string, commands: string[], target = "dev"): string {
  const s = stack();
  const steps = commands.map((command, i) => ({ n: i + 1, kind: command.startsWith("git ") ? "git" : command.startsWith("docker ") ? "docker" : "shell", command, purpose: `Step ${i + 1}`, cwd: "/srv/dev/myapp", timeout_s: 120 }));
  const file = join(s.root, `plan-${n++}.json`);
  writeFileSync(file, JSON.stringify({ goal, target, steps }));
  return warden("plan", "propose", "--as", "claude-code", "--file", file).split(/\s+/)[0]!;
}

/** A CTAP2 platform authenticator with user verification, shared by every page in the context. */
export async function authenticator(page: Page): Promise<{ cdp: CDPSession; id: string }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  return { cdp, id: authenticatorId };
}

/** Fail the test if the page talks to anything but the stack's own origin (README 16 rule 15). */
export async function localOnly(context: BrowserContext, seen: string[]): Promise<void> {
  await context.route("**/*", (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== stack().origin && url.protocol !== "data:") {
      seen.push(url.href);
      return route.abort();
    }
    return route.continue();
  });
}

/** Sign a pending publish file with the offline key, as the operator does on the offline machine. */
export function offlineSign(bundle: string, version: number): string {
  const s = stack();
  const file = join(s.root, `bundle-v${version}.json`);
  writeFileSync(file, bundle);
  execFileSync(s.sign, ["sign", file, "--key", s.offlineKey, "--passphrase-file", s.passphrase, "--yes"], { encoding: "utf8" });
  return join(s.root, `bundle-v${version}.sig.json`);
}
