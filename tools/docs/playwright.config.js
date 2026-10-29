import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests', fullyParallel: true, workers: 3,
  use: { baseURL: 'http://127.0.0.1:50331/Bower/', viewport: { width: 1440, height: 1000 }, screenshot: 'only-on-failure' },
  webServer: { command: 'python3 serve.py', url: 'http://127.0.0.1:50331/Bower/', reuseExistingServer: !process.env.CI },
  reporter: [['list']],
});
