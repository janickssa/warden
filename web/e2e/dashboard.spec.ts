// The dashboard against a real `warden serve`, in order, like one operator: M6 Done-when first (register
// a passkey, sign in, approve with it, publish a tightening), then states, keyboard, the prototype bug
// fixes, phone layout and Danish. Passkeys come from a virtual authenticator; nothing leaves localhost.
import { type BrowserContext, expect, type Page, test } from "@playwright/test";
import { authenticator, localOnly, offlineSign, propose, registrationLink, warden } from "./warden";

test.describe.configure({ mode: "serial" });

let context: BrowserContext;
let page: Page;
const outside: string[] = [];

test.beforeAll(async ({ browser }) => {
  context = await browser.newContext();
  await localOnly(context, outside);
  page = await context.newPage();
  await authenticator(page);
});
test.afterAll(async () => {
  await context.close();
});

const scrollToEnd = () => page.locator("#main").evaluate((m) => m.scrollTo(0, m.scrollHeight));
const usePasskey = async () => page.getByTestId("passkey-dialog").getByRole("button", { name: "Use passkey" }).click();

test("Done-when: register a passkey, sign in, approve with it, publish a tightening", async () => {
  // Register the first passkey from the one-time link `warden passkey add` prints.
  await page.goto(registrationLink("Tester"));
  await page.getByRole("button", { name: "Create passkey" }).click();
  await expect(page.getByText("Passkey “Tester” registered.")).toBeVisible();

  // Sign in with it; the session cookie is httpOnly, so the page can't read it.
  await page.getByRole("link", { name: "Sign in" }).click();
  await page.getByRole("button", { name: "Sign in with passkey" }).click();
  await expect(page).toHaveURL(/\/approvals$/);
  expect(await page.evaluate(() => document.cookie)).toBe("");

  // Claude proposes; the card appears live. Approve unlocks only at the end of the steps.
  const id = propose("Update and test the dev app", ["git pull", "npm ci", "npm test"]);
  const card = page.locator(`[data-plan="${id}"]`);
  await expect(card).toBeVisible({ timeout: 10_000 });
  await card.click();
  await expect(page).toHaveURL(new RegExp(`/plans/${id}\\?from=approvals`));
  await expect(page.locator('[data-nav="approvals"]')).toHaveAttribute("aria-current", "page");
  await scrollToEnd();
  const approve = page.getByTestId("approve");
  await expect(approve).toBeEnabled();
  // The stack's only reviewer can't answer, so the plan is high risk and approving needs the passkey.
  await expect(approve).toContainText("Approve & sign…");
  await approve.click();
  await expect(page.getByTestId("passkey-dialog")).toContainText("High-risk plan");
  await usePasskey();
  await expect(page.getByTestId("plan-info")).toContainText(/Approved \d\d:\d\d/, { timeout: 10_000 });
  expect(warden("plan", "show", id)).toMatch(/approved|held/);
  await expect(page.getByTestId("approval-summary")).toContainText("Plan hash");

  // Registering the passkey added an approver: a loosening, waiting for the offline signature. Sign the
  // downloaded bundle with the offline key and upload it on the Policy page.
  await page.locator('[data-nav="policy"]').click();
  await expect(page.getByTestId("rollout")).toBeVisible();
  const pending = page.getByTestId("pending-bundle");
  if (await pending.isVisible({ timeout: 2_000 }).catch(() => false)) {
    const res = await page.request.get("/api/policy/pending/file");
    const bundle = await res.text();
    const sig = offlineSign(bundle, JSON.parse(bundle).version);
    await pending.getByRole("button", { name: "Upload signature…" }).click();
    await page.getByTestId("signature-file").setInputFiles(sig);
    await page.getByRole("button", { name: "Verify & publish" }).click();
    await expect(page.getByRole("status")).toContainText(/Offline signature verified · v\d+ rolling out/, { timeout: 15_000 });
    await expect(pending).toHaveCount(0);
  }

  // Publish a tightening from the Policy page: add a denied path, see Warden classify it, passkey.
  const field = page.locator('[data-field="deny_paths"] input');
  await field.fill("/srv/secret");
  await field.press("Enter");
  await expect(page.getByTestId("changes")).toContainText("↓ Tighten", { timeout: 15_000 });
  await expect(page.getByTestId("changes")).toContainText(/policy tests passed/);
  await page.getByTestId("publish").click();
  await usePasskey();
  await expect(page.getByRole("status")).toContainText(/Policy v\d+ published · rolling out/, { timeout: 15_000 });
  await expect(page.getByTestId("policy-hint")).toContainText(/No changes · v\d+ is live/);
  expect(warden("policy", "status")).toMatch(/policy v\d+/);
});

test("loosening is never published on the online key", async () => {
  const field = page.locator('[data-field="commands.allow.git.subcommands"] input');
  await field.fill("push");
  await field.press("Enter");
  await expect(page.getByTestId("changes")).toContainText("↑ Loosen", { timeout: 15_000 });
  await expect(page.getByTestId("publish")).toContainText("Create bundle for offline signing…");
  await page.getByRole("button", { name: "Discard", exact: true }).click();
  await expect(page.getByTestId("policy-hint")).toContainText(/No changes/);
});

test("bug 1: a plan opened from Plans belongs to Plans, and the back link agrees", async () => {
  const id = propose("Check the dev app", ["git status"]);
  await page.locator('[data-nav="plans"]').click();
  await page.locator(`[data-plan="${id}"]`).click();
  await expect(page.locator('[data-nav="plans"]')).toHaveAttribute("aria-current", "page");
  await expect(page.getByTestId("back")).toHaveText(/Plans/);
  await expect(page.getByTestId("back")).toHaveAttribute("href", "/plans");
  // Opened from somewhere that isn't a plan list (here Groups via ?from=groups): still a plan list.
  await page.goto(`/plans/${id}?from=groups`);
  await expect(page.locator('[data-nav="approvals"]')).toHaveAttribute("aria-current", "page");
  await expect(page.getByTestId("back")).toHaveAttribute("href", "/approvals");
});

test("keyboard: ? lists shortcuts, Esc closes, r rejects, there is no approve key", async () => {
  await page.locator("body").press("?");
  await expect(page.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeVisible();
  await expect(page.getByText("There is deliberately no shortcut for Approve.")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.keyboard.press("a");
  await expect(page.getByTestId("plan-info")).toHaveCount(0); // still awaiting: nothing approved it
  await page.keyboard.press("r");
  const reject = page.getByTestId("reject-dialog");
  await reject.getByLabel("Reason (optional)").fill("Use port 3001 instead");
  await reject.getByRole("button", { name: "Reject plan" }).click();
  await expect(page).toHaveURL(/\/approvals$/);
  await expect(page.getByRole("status")).toContainText("Plan rejected · Claude has been told");
});

test("offline: banner, stale data, every action disabled", async () => {
  const id = propose("Run the tests", ["npm test"]);
  await page.locator(`[data-plan="${id}"]`).click();
  await scrollToEnd();
  await expect(page.getByTestId("approve")).toBeEnabled();
  // Warden goes away (WireGuard down): requests fail and the socket can't reconnect.
  let down = true;
  await page.route("**/api/**", (r) => (down ? r.abort("connectionrefused") : r.fallback()));
  await page.routeWebSocket(/\/ws$/, (ws) => {
    if (down) ws.close();
    else ws.connectToServer();
  });
  await page.locator('[data-nav="plans"]').click();
  await expect(page.getByTestId("offline-banner")).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText(/Stale · last updated \d\d:\d\d/)).toBeVisible();
  await page.goBack();
  await expect(page.getByTestId("approve")).toBeDisabled();
  await expect(page.getByRole("button", { name: "Reject" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Lockdown" })).toBeDisabled();
  await expect(page.getByText("Read-only while Warden is unreachable.")).toBeVisible();
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByRole("status")).toContainText("Still can’t reach Warden", { timeout: 5_000 });
  // Back again: the banner goes away by itself.
  down = false;
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByTestId("offline-banner")).toHaveCount(0, { timeout: 20_000 });
  await scrollToEnd();
  await expect(page.getByTestId("approve")).toBeEnabled();
});

test("bug 2: on a phone the action bar never covers the last step", async () => {
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole("button", { name: "Approve with edits" })).toHaveCount(0); // phone layout applied
  await scrollToEnd();
  const bar = await page.getByTestId("actionbar").boundingBox();
  const steps = page.locator("[data-step]");
  const last = await steps.nth((await steps.count()) - 1).boundingBox();
  expect(bar && last).toBeTruthy();
  expect(last!.y + last!.height).toBeLessThanOrEqual(bar!.y + 1);
  await expect(page.getByRole("button", { name: "Approve with edits" })).toHaveCount(0);
  // Pages other than Approvals and Plan detail are desktop-only.
  await page.goto("/policy");
  await expect(page.getByText("Policy isn’t available in a phone browser")).toBeVisible();
  await page.setViewportSize({ width: 1280, height: 900 });
});

test("bug 3: an unavailable gatekeeper shows everywhere and counts as escalate", async () => {
  await page.goto("/approvals");
  const id = propose("Show the log", ["git log"]);
  const card = page.locator(`[data-plan="${id}"]`);
  await expect(card).toContainText("Gatekeepers: ▲ Escalate", { timeout: 15_000 });
  await expect(page.getByTestId("gatekeepers")).toContainText("local○");
  await card.click();
  const row = page.locator('[data-reviewer="local"]');
  await expect(row).toContainText("○ Unavailable · counted as escalate");
  await expect(page.getByTestId("verdicts")).toContainText("Final, strictest wins: ▲ Escalate");
});

test("Dansk: the language setting switches the dashboard", async () => {
  await page.goto("/settings");
  await page.locator("label.seg-opt", { hasText: "Dansk" }).click();
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.locator('[data-nav="approvals"]')).toContainText("Godkendelser", { timeout: 10_000 });
  await page.locator("label.seg-opt", { hasText: "English" }).click();
  await page.getByRole("button", { name: "Gem ændringer" }).click();
  await expect(page.locator('[data-nav="approvals"]')).toContainText("Approvals", { timeout: 10_000 });
});

test("audit log verifies the chain and records what happened", async () => {
  await page.locator('[data-nav="audit"]').click();
  await expect(page.getByTestId("chain")).toContainText("✓ Hash chain verified");
  await expect(page.locator("[data-audit]").first()).toBeVisible();
  await page.locator("label.seg-opt", { hasText: "Settings & access" }).click();
  await expect(page.locator("[data-audit]", { hasText: "setting_changed" }).first()).toBeVisible();
});

test("no request ever left the dashboard's origin", () => {
  expect(outside).toEqual([]);
});
