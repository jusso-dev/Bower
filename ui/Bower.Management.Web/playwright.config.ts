import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.BOWER_UI_BASE_URL ?? "http://127.0.0.1:4320";

export default defineConfig({
  testDir: "./e2e",
  outputDir: "./test-results",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  reporter: [["list"], ["html", { open: "never" }]],
  expect: {
    timeout: 8_000
  },
  use: {
    baseURL,
    colorScheme: "light",
    locale: "en-AU",
    timezoneId: "Australia/Sydney",
    contextOptions: {
      reducedMotion: "reduce"
    },
    screenshot: "only-on-failure",
    trace: "on-first-retry"
  },
  // BOWER_E2E_CANARY=1: the management API under test sends setup canaries to this stub
  // (Bower:Setup:Canary:CollectorUrl=http://127.0.0.1:4399/), so the wizard can reach a
  // simulated proof without Azure.
  webServer: process.env.BOWER_E2E_CANARY === "1"
    ? {
        command: "node e2e/stub-collector.mjs",
        url: "http://127.0.0.1:4399/health",
        reuseExistingServer: !process.env.CI
      }
    : undefined,
  projects: [
    {
      name: "readme-chromium",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1440, height: 1000 }
      }
    },
    {
      name: "mobile-chromium",
      use: {
        ...devices["Pixel 7"]
      }
    }
  ]
});
