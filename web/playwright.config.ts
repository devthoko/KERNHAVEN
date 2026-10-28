import { defineConfig, devices } from "@playwright/test";

// Run through scripts/e2e.sh, which starts a real kernhaven-core with a fresh
// database and passes its URL and setup token.
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  // The github reporter turns failures into public check annotations.
  reporter: process.env.CI ? [["list"], ["github"]] : [["list"]],
  use: {
    baseURL: process.env.KH_BASE_URL ?? "http://localhost:18471",
    trace: "retain-on-failure",
    // No animations: axe measures final colors, not mid-transition ones.
    contextOptions: { reducedMotion: "reduce" },
    // Routes of the reverse proxy test (M12): *.kh.test resolves to this
    // machine, served by Caddy with its internal CA.
    ignoreHTTPSErrors: true,
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], launchOptions: { args: ["--host-resolver-rules=MAP *.kh.test 127.0.0.1"] } },
    },
  ],
});
