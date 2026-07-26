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
