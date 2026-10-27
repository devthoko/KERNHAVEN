import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";

// One ordered journey through a fresh instance (setup → owner → viewer).
// The owner signs in once and the session is reused: the login rate limit
// (10 attempts per minute and address, AT-F08-02) also applies to tests.
test.describe.configure({ mode: "serial" });

const token = process.env.KH_SETUP_TOKEN ?? "";
const OWNER = { username: "owner", password: "correct horse battery staple" };
const VIEWER = { username: "viewer1", password: "another long viewer passphrase" };

let ownerContext: BrowserContext;
let page: Page;
let problems: string[] = [];

// Collects CSP violations and uncaught errors.
function watch(p: Page, sink: string[]) {
  p.on("console", (m) => {
    if (m.type() === "error" && /Content Security Policy|Refused to/i.test(m.text())) sink.push(m.text());
  });
  p.on("pageerror", (e) => sink.push(e.message));
}

async function expectAccessible(p: Page, label: string) {
  const results = await new AxeBuilder({ page: p }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  const serious = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(serious.map((v) => `${label}: ${v.id} ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
}

async function expectNoHorizontalOverflow(p: Page, label: string) {
  const overflow = await p.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow, `${label} overflows horizontally by ${overflow}px`).toBeLessThanOrEqual(0);
}

async function login(p: Page, user: { username: string; password: string }) {
  await p.goto("/login");
  await p.getByLabel("Username").fill(user.username);
  await p.getByLabel("Password").fill(user.password);
  await p.getByRole("button", { name: "Sign in" }).click();
  await expect(p.getByRole("heading", { name: "Dashboard" })).toBeVisible();
}

async function freshLogin(browser: Browser, user: { username: string; password: string }) {
  const ctx = await browser.newContext();
  const p = await ctx.newPage();
  await login(p, user);
  return p;
}

test.beforeAll(async ({ browser }) => {
  ownerContext = await browser.newContext();
  page = await ownerContext.newPage();
  watch(page, problems);
});

test.afterEach(() => {
  expect(problems, "CSP violations or page errors").toEqual([]);
  problems = [];
});

test.afterAll(async () => {
  await ownerContext.close();
});

test("AT-F08-01, AT-F01-04: first-run setup works by keyboard and is accessible", async () => {
  expect(token, "KH_SETUP_TOKEN must be set").not.toBe("");
  await page.goto("/");
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.getByRole("heading", { name: "Set up Kernhaven" })).toBeVisible();
  await expectAccessible(page, "setup");

  // Keyboard only: the token field has focus; Tab moves through the form.
  await expect(page.getByLabel("Setup token")).toBeFocused();
  await page.keyboard.type(token);
  await page.keyboard.press("Tab");
  await page.keyboard.type(OWNER.username);
  await page.keyboard.press("Tab"); // display name (optional)
  await page.keyboard.press("Tab");
  await page.keyboard.type(OWNER.password);
  await page.keyboard.press("Tab");
  await page.keyboard.type(OWNER.password);
  await page.keyboard.press("Enter");

  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("Ready", { exact: true })).toBeVisible();
  // No agent runs in this environment: the dashboard says so instead of failing.
  await expect(page.getByText("Host agent")).toBeVisible();
  await expect(page.getByText("Unavailable", { exact: true })).toBeVisible();
  await expectAccessible(page, "dashboard");
});

test("AT-F08-06: owner creates a viewer through the UI", async () => {
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Users" }).click();
  await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();
  await page.getByRole("button", { name: "New user" }).click();
  const dialog = page.getByRole("dialog", { name: "New user" });
  await expect(dialog).toBeVisible();
  await expectAccessible(page, "new user dialog");
  await dialog.getByLabel("Username").fill(VIEWER.username);
  await dialog.getByLabel("Role").selectOption("viewer");
  await dialog.getByLabel("Initial password").fill(VIEWER.password);
  await dialog.getByRole("button", { name: "Create user" }).click();
  await expect(page.getByText(`User ${VIEWER.username} created.`)).toBeVisible();
  await expect(page.getByRole("row", { name: new RegExp(`\\b${VIEWER.username}\\b`) })).toHaveCount(1);

  // Server-side validation errors are shown in the dialog.
  await page.getByRole("button", { name: "New user" }).click();
  await dialog.getByLabel("Username").fill(VIEWER.username);
  await dialog.getByLabel("Initial password").fill(VIEWER.password);
  await dialog.getByRole("button", { name: "Create user" }).click();
  await expect(dialog.getByRole("alert")).toContainText("already exists");
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expectAccessible(page, "users");
});

test("AT-F18-03: jobs are listed with their journal and log", async () => {
  await page.goto("/jobs");
  await expect(page.getByRole("heading", { name: "Jobs", exact: true })).toBeVisible();
  const link = page.getByRole("link", { name: /maintenance\.purge_sessions/ }).first();
  await expect(link).toBeVisible();
  await expectAccessible(page, "jobs");
  await link.click();
  await expect(page.getByRole("heading", { name: /Job #\d+/ })).toBeVisible();
  await expect(page.getByText("delete expired sessions", { exact: false }).first()).toBeVisible();
  await expect(page.getByText("Succeeded", { exact: true })).toBeVisible();
  await expect(page.getByText(/all steps completed/)).toBeVisible();
  await expectAccessible(page, "job detail");
});

test("AT-F10-03 (partial): audit log lists events and verifies the chain", async () => {
  await page.goto("/audit");
  await expect(page.getByRole("heading", { name: "Audit log" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "auth.setup", exact: true })).toBeVisible();
  await page.getByLabel("Action", { exact: true }).fill("user.create");
  await page.getByRole("button", { name: "Filter" }).click();
  await expect(page.getByRole("cell", { name: "user.create", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "auth.setup", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Verify integrity" }).click();
  await expect(page.getByText(/Integrity verified: \d+ records/)).toBeVisible();
  await expectAccessible(page, "audit");
});

test("AT-F08-05: a user sees and revokes their other sessions", async ({ browser }) => {
  const other = await freshLogin(browser, OWNER);
  await page.goto("/account");
  const table = page.getByRole("table", { name: "Your active sessions" });
  await expect(table.getByRole("button", { name: /Revoke session/ })).toHaveCount(1);
  await expect(table.getByText("This device")).toBeVisible();
  await table.getByRole("button", { name: /Revoke session/ }).click();
  await expect(table.getByRole("button", { name: /Revoke session/ })).toHaveCount(0);
  await other.goto("/users");
  await expect(other.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await other.context().close();
});

test("AT-F01-02: pages fit 360, 768 and 1440 px without horizontal overflow", async () => {
  for (const width of [360, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    for (const path of ["/", "/jobs", "/users", "/audit", "/account"]) {
      await page.goto(path);
      await expect(page.locator("h1")).toBeVisible();
      await expectNoHorizontalOverflow(page, `${path}@${width}`);
      // Navigation must be reachable at every width.
      if (width < 768) {
        await page.getByRole("button", { name: "Menu" }).click();
        await expect(page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Account" })).toBeVisible();
        await page.getByRole("button", { name: "Close" }).click();
      } else {
        await expect(page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Account" })).toBeVisible();
      }
    }
  }
  await page.setViewportSize({ width: 1280, height: 720 });
});

test("AT-F01-03: theme preference is stored per user", async () => {
  await page.goto("/account");
  await page.getByLabel("Dark", { exact: true }).check();
  await expect(page.locator("html")).toHaveClass(/dark/);
  await expectAccessible(page, "account (dark)");
  await page.getByRole("button", { name: "Sign out" }).first().click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(page.locator("html")).not.toHaveClass(/dark/);
  await expectAccessible(page, "login");
  await login(page, OWNER);
  await expect(page.locator("html")).toHaveClass(/dark/);
  await page.goto("/account");
  await page.getByLabel("System", { exact: true }).check();
  await expect(page.locator("html")).not.toHaveClass(/dark/);
});

test("AT-F09-01 (UI): a viewer only sees what the role allows", async ({ browser }) => {
  const viewer = await freshLogin(browser, VIEWER);
  const nav = viewer.getByRole("navigation", { name: "Main" });
  await expect(nav.getByRole("link", { name: "Jobs" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Users" })).toHaveCount(0);
  await expect(nav.getByRole("link", { name: "Audit log" })).toHaveCount(0);
  await viewer.goto("/users");
  await expect(viewer.getByRole("heading", { name: "Page not found" })).toBeVisible();
  await viewer.goto("/jobs");
  await viewer.getByRole("link", { name: /maintenance\./ }).first().click();
  await expect(viewer.getByRole("heading", { name: /Job #\d+/ })).toBeVisible();
  await expect(viewer.getByRole("button", { name: "Cancel job" })).toHaveCount(0);
  await viewer.context().close();
});
