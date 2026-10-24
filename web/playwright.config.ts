import { defineConfig } from "@playwright/test";

const PORT = Number(process.env.WARDEN_E2E_PORT ?? 3900);

// One real Warden (e2e/stack.mjs) for the whole run; tests share it in order, like one operator would.
export default defineConfig({
  testDir: "e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  reporter: [["list"]],
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: "retain-on-failure",
    launchOptions: process.env.PW_CHROMIUM ? { executablePath: process.env.PW_CHROMIUM } : {},
  },
  webServer: {
    command: "node e2e/stack.mjs",
    url: `http://localhost:${PORT}/sign-in`,
    reuseExistingServer: false,
    timeout: 180_000,
    stdout: "pipe",
  },
});
