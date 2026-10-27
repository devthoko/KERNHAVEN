import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Browser, type Page } from "@playwright/test";

// One ordered journey through a fresh instance (setup → owner → viewer).
test.describe.configure({ mode: "serial" });

const token = process.env.KH_SETUP_TOKEN ?? "";
const OWNER = { username: "owner", password: "correct horse battery staple" };
const VIEWER = { username: "viewer1", password: "another long viewer passphrase" };

// Collects CSP violations and uncaught errors for the whole test.
function watch(page: Page) {
  const problems: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error" && /Content Security Policy|Refused to/i.test(m.text())) problems.push(m.text());
  });
  page.on("pageerror", (e) => problems.push(e.message));
  return problems;
}

async function expectAccessible(page: Page, label: string) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  const serious = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(serious.map((v) => `${label}: ${v.id} ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
}

async function expectNoHorizontalOverflow(page: Page, label: string) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow, `${label} overflows horizontally by ${overflow}px`).toBeLessThanOrEqual(0);
}

async function login(page: Page, user: { username: string; password: string }) {
  await page.goto("/login");
  await page.getByLabel("Username").fill(user.username);
  await page.getByLabel("Password").fill(user.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
}

async function newLoggedInPage(browser: Browser, user: { username: string; password: string }) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await login(page, user);
  return page;
}

test("AT-F08-01, AT-F01-04: first-run setup works by keyboard and is accessible", async ({ page }) => {
  expect(token, "KH_SETUP_TOKEN must be set").not.toBe("");
  const problems = watch(page);
  await page.goto("/");
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.getByRole("heading", { name: "Set up Kernhaven" })).toBeVisible();
  await expectAccessible(page, "setup");

  // Keyboard only: the token field has focus; Tab moves through the form.
  await expect(page.getByLabel("Setup token")).toBeFocused();
  await page.keyboard.type(token);
  await page.keyboard.press("Tab");
  await page.keyboard.type(OWNER.username);
  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");
  await page.keyboard.type(OWNER.password);
  await page.keyboard.press("Tab");
  await page.keyboard.type(OWNER.password);
  await page.keyboard.press("Enter");

  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("Ready")).toBeVisible();
  await expectAccessible(page, "dashboard");
  expect(problems).toEqual([]);
});

test("AT-F08-06: owner creates a viewer through the UI", async ({ page }) => {
  const problems = watch(page);
  await login(page, OWNER);
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
  await expect(page.getByRole("cell", { name: new RegExp(VIEWER.username) })).toBeVisible();

  // Server-side validation errors are shown.
  await page.getByRole("button", { name: "New user" }).click();
  await dialog.getByLabel("Username").fill(VIEWER.username);
  await dialog.getByLabel("Initial password").fill(VIEWER.password);
  await dialog.getByRole("button", { name: "Create user" }).click();
  await expect(dialog.getByRole("alert")).toContainText("already exists");
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expectAccessible(page, "users");
  expect(problems).toEqual([]);
});

test("AT-F18-03: jobs are listed with their journal and log", async ({ page }) => {
  const problems = watch(page);
  await login(page, OWNER);
  await page.goto("/jobs");
  await expect(page.getByRole("heading", { name: "Jobs" })).toBeVisible();
  const link = page.getByRole("link", { name: /maintenance\.purge_sessions/ }).first();
  await expect(link).toBeVisible();
  await expectAccessible(page, "jobs");
  await link.click();
  await expect(page.getByRole("heading", { name: /Job #\d+/ })).toBeVisible();
  await expect(page.getByText("delete expired sessions")).toBeVisible();
  await expect(page.getByText("Succeeded")).toBeVisible();
  await expect(page.getByText(/all steps completed/)).toBeVisible();
  await expectAccessible(page, "job detail");
  expect(problems).toEqual([]);
});

test("AT-F10-03 (partial): audit log lists events and verifies the chain", async ({ page }) => {
  const problems = watch(page);
  await login(page, OWNER);
  await page.goto("/audit");
  await expect(page.getByRole("heading", { name: "Audit log" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "auth.setup" })).toBeVisible();
  await page.getByLabel("Action").fill("user.create");
  await page.getByRole("button", { name: "Filter" }).click();
  await expect(page.getByRole("cell", { name: "user.create" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "auth.setup" })).toBeHidden();
  await page.getByRole("button", { name: "Verify integrity" }).click();
  await expect(page.getByText(/Integrity verified: \d+ records/)).toBeVisible();
  await expectAccessible(page, "audit");
  expect(problems).toEqual([]);
});

test("AT-F01-03: theme preference is stored per user", async ({ page }) => {
  await login(page, OWNER);
  await page.goto("/account");
  await page.getByLabel("Dark").check();
  await expect(page.locator("html")).toHaveClass(/dark/);
  await expectAccessible(page, "account (dark)");
  await page.getByRole("button", { name: "Sign out" }).first().click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(page.locator("html")).not.toHaveClass(/dark/);
  await login(page, OWNER);
  await expect(page.locator("html")).toHaveClass(/dark/);
  await page.goto("/account");
  await page.getByLabel("System").check();
  await expect(page.locator("html")).not.toHaveClass(/dark/);
});

test("AT-F08-05: a user sees and revokes their other sessions", async ({ page, browser }) => {
  await login(page, OWNER);
  const other = await newLoggedInPage(browser, OWNER);
  await page.goto("/account");
  const rows = page.getByRole("table", { name: "Your active sessions" }).getByRole("row");
  await expect(rows).toHaveCount(3); // header + 2 sessions
  await page.getByRole("button", { name: /Revoke session/ }).first().click();
  await expect(rows).toHaveCount(2);
  await other.goto("/users");
  await expect(other.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await other.context().close();
});

test("AT-F09-01 (UI): a viewer only sees what the role allows", async ({ page }) => {
  await login(page, VIEWER);
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByRole("link", { name: "Jobs" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Users" })).toHaveCount(0);
  await expect(nav.getByRole("link", { name: "Audit log" })).toHaveCount(0);
  await page.goto("/users");
  await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
  await page.goto("/jobs");
  await page.getByRole("link", { name: /maintenance\./ }).first().click();
  await expect(page.getByRole("heading", { name: /Job #\d+/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Cancel job" })).toHaveCount(0);
});

test("AT-F01-02: pages fit 360, 768 and 1440 px without horizontal overflow", async ({ browser }) => {
  for (const width of [360, 768, 1440]) {
    const ctx = await browser.newContext({ viewport: { width, height: 900 } });
    const page = await ctx.newPage();
    await page.goto("/login");
    await expectNoHorizontalOverflow(page, `login@${width}`);
    await page.getByLabel("Username").fill(OWNER.username);
    await page.getByLabel("Password").fill(OWNER.password);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
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
    await ctx.close();
  }
});
