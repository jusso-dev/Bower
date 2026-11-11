import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests', fullyParallel: true, workers: 3,
  use: { baseURL: 'http://127.0.0.1:50331/Bower/', viewport: { width: 1440, height: 1000 }, screenshot: 'only-on-failure',
    // Linux on every machine, so platform-dependent UI (the search hint shows Ctrl K, not
    // Cmd K on macOS) is the same locally as in CI.
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36' },
  webServer: { command: 'python3 serve.py', url: 'http://127.0.0.1:50331/Bower/', reuseExistingServer: !process.env.CI },
  reporter: [['list']],
});
