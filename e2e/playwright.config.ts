import { defineConfig } from "@playwright/test";

// E2E_SIGNAL_MODE=mock (default, offline) or jev (real Jev API, needs API_KEY_JEV).
const signalMode = process.env.E2E_SIGNAL_MODE ?? "mock";
const port = process.env.E2E_PORT ?? "18080";
const baseURL = `http://127.0.0.1:${port}`;
// E2E_DEMO=1 adds the recorded browser walkthrough (needs `npx playwright install chromium`).
const demo = Boolean(process.env.E2E_DEMO);

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  use: { baseURL, extraHTTPHeaders: { "content-type": "application/json" } },
  projects: [
    { name: "api", testMatch: /personas\.spec\.ts/ },
    ...(demo
      ? [
          {
            name: "demo",
            testMatch: /demo\.spec\.ts/,
            use: {
              browserName: "chromium" as const,
              viewport: { width: 1280, height: 720 },
              video: { mode: "on" as const, size: { width: 1280, height: 720 } },
            },
          },
        ]
      : []),
  ],
  webServer: {
    command: "cargo run --quiet",
    cwd: "../app",
    url: `${baseURL}/healthz`,
    timeout: 300_000,
    reuseExistingServer: !process.env.CI,
    env: {
      SIGNAL_MODE: signalMode,
      BIND_ADDR: `127.0.0.1:${port}`,
      POLICY_PATH: "policy.yaml",
      RUST_LOG: "warn",
    },
  },
});
