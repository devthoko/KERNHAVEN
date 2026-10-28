import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { createHmac, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { connect } from "node:tls";

// One ordered journey through a fresh instance (setup → owner → viewer).
// The owner signs in once and the session is reused: the login rate limit
// (10 attempts per minute and address, AT-F08-02) also applies to tests.
test.describe.configure({ mode: "serial" });

const token = process.env.KH_SETUP_TOKEN ?? "";
const OWNER = { username: "owner", password: "correct horse battery staple" };
const VIEWER = { username: "viewer1", password: "another long viewer passphrase" };
// Set by scripts/e2e.sh when a real agent with Docker runs (always in CI).
const docker = process.env.KH_E2E_DOCKER === "1";

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
  await p.getByRole("button", { name: "Sign in", exact: true }).click();
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
  await expect(page.getByText("Host agent", { exact: true })).toBeVisible();
  await expect(page.getByText(docker ? "Connected" : "Unavailable", { exact: true })).toBeVisible();
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

test("AT-F02-05: pull an image through the UI", async () => {
  test.skip(!docker, "needs the agent with Docker (always present in CI)");
  await page.goto("/images");
  await expect(page.getByRole("heading", { name: "Images", exact: true })).toBeVisible();
  await expectAccessible(page, "images");
  await page.getByLabel("Image reference").fill("alpine:3");
  await page.getByRole("button", { name: "Pull", exact: true }).click();
  await page.getByRole("link", { name: /Follow job #\d+/ }).click();
  await expect(page.getByText("Succeeded", { exact: true })).toBeVisible({ timeout: 120_000 });
  await expect(page.getByText(/pulled alpine:3 → .*@sha256:/)).toBeVisible();
});

test("AT-F02-04: the create form shows policy findings and exceptions", async () => {
  test.skip(!docker, "needs the agent with Docker");
  await page.goto("/containers/new");
  await page.getByLabel("Name", { exact: true }).fill("e2e-web");
  await page.getByLabel("Image", { exact: true }).fill("alpine:3");
  await page.getByLabel("User (optional)").fill("65534");
  await page.getByLabel("Memory limit (MiB, 0 = none)").fill("64");
  await page.getByLabel("Command (one argument per line)").fill("sh\n-c\necho e2e-hello; sleep 600");
  await expect(page.getByText("No policy violations.")).toBeVisible();
  await expect(page.getByText(/not pinned by digest/)).toBeVisible();
  await page.getByLabel("Privileged mode").check();
  await expect(page.getByText("Violation: privileged")).toBeVisible();
  await expect(page.getByRole("button", { name: "Create container" })).toBeDisabled();
  await expect(page.getByLabel("Approve an exception (audited)")).toBeVisible();
  await expectAccessible(page, "new container (violation)");
  await page.getByLabel("Privileged mode").uncheck();
  await expect(page.getByText("No policy violations.")).toBeVisible();
});

test("AT-F02-02, AT-F02-03: create, inspect, read logs, stop and start a container", async () => {
  test.skip(!docker, "needs the agent with Docker");
  await page.getByRole("button", { name: "Create container" }).click();
  await expect(page.getByRole("heading", { name: "e2e-web" })).toBeVisible();
  await expect(page.getByText("running", { exact: true }).first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText(/created by owner/)).toBeVisible();
  await expect(page.getByLabel("Container log output")).toContainText("e2e-hello", { timeout: 15_000 });
  await expectAccessible(page, "container detail");
  await page.getByRole("button", { name: "Stop", exact: true }).click();
  await expect(page.getByText("exited", { exact: true }).first()).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: "Start", exact: true }).click();
  await expect(page.getByText("running", { exact: true }).first()).toBeVisible({ timeout: 30_000 });

  await page.goto("/containers");
  await expect(page.getByRole("link", { name: "e2e-web" })).toBeVisible();
  await expectAccessible(page, "containers");
});

test("AT-F02-06: volumes and networks", async () => {
  test.skip(!docker, "needs the agent with Docker");
  await page.goto("/volumes");
  await page.getByLabel("New volume name").fill("e2e-vol");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByRole("row", { name: /e2e-vol/ })).toHaveCount(1);
  await expectAccessible(page, "volumes");
  await page.getByRole("button", { name: "Remove volume e2e-vol" }).click();
  await page.getByLabel('Type "e2e-vol" to confirm').fill("e2e-vol");
  await page.getByRole("button", { name: "Remove volume and its data", exact: true }).click();
  await expect(page.getByRole("row", { name: /e2e-vol/ })).toHaveCount(0);

  await page.goto("/networks");
  await page.getByLabel("New network name").fill("e2e-net");
  await page.getByLabel(/Internal/).check();
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByRole("row", { name: /e2e-net/ })).toContainText("internal");
  await expectAccessible(page, "networks");
  await page.getByRole("button", { name: "Remove network e2e-net" }).click();
  await page.getByLabel('Type "e2e-net" to confirm').fill("e2e-net");
  await page.getByRole("button", { name: "Remove network", exact: true }).click();
  await expect(page.getByRole("row", { name: /e2e-net/ })).toHaveCount(0);
});

test("AT-F02-02: remove a container with typed confirmation", async () => {
  test.skip(!docker, "needs the agent with Docker");
  await page.goto("/containers/e2e-web");
  await page.getByRole("button", { name: "Remove", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Remove container" });
  await expect(dialog.getByRole("button", { name: "Remove container" })).toBeDisabled();
  await dialog.getByLabel('Type "e2e-web" to confirm').fill("e2e-web");
  await dialog.getByRole("button", { name: "Remove container" }).click();
  await expect(page.getByRole("heading", { name: "Containers", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "e2e-web" })).toHaveCount(0);
});

const stackCompose = (cmd: string) => `services:
  app:
    image: alpine:3
    user: "65534"
    mem_limit: 64m
    command: ["sh", "-c", "${cmd}"]
    volumes: [data:/data]
  worker:
    image: alpine:3
    user: "65534"
    mem_limit: 32m
    command: ["sleep", "600"]
    depends_on: [app]
volumes:
  data:
`;

async function waitStackStatus(p: Page, status: string) {
  await expect(p.getByText(status, { exact: true }).first()).toBeVisible({ timeout: 120_000 });
}

test("AT-F03-01, AT-F03-02: the stack editor reports errors with line numbers", async () => {
  test.skip(!docker, "needs the agent with Docker");
  await page.goto("/stacks/new");
  await page.getByLabel("Stack name").fill("e2e-stack");
  await page.getByLabel("compose.yaml").fill("services:\n  app:\n    image: alpine:3\n    build: .\n");
  await expect(page.getByRole("button", { name: /Line 4: services.app.build/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Create and deploy" })).toBeDisabled();
  await expectAccessible(page, "new stack (error)");
});

test("AT-F03-05, AT-F03-06: create and deploy a stack with a variable", async () => {
  test.skip(!docker, "needs the agent with Docker");
  await page.getByLabel("compose.yaml").fill(stackCompose("echo app-$${GREETING}; sleep 600".replace("$$", "$")));
  await page.getByRole("button", { name: "Add variable" }).click();
  await page.getByLabel("Name", { exact: true }).fill("GREETING");
  await page.getByLabel("Value", { exact: true }).fill("hello");
  await expect(page.getByText("Valid and allowed by the container policy.")).toBeVisible();
  await page.getByRole("button", { name: "Create and deploy" }).click();
  await expect(page.getByRole("heading", { name: "e2e-stack" })).toBeVisible();
  await waitStackStatus(page, "deployed");
  await expect(page.getByRole("table", { name: "Services" }).getByText("running")).toHaveCount(2, { timeout: 30_000 });
  await expectAccessible(page, "stack detail");
});

test("AT-F03-04, AT-F03-05: a new revision is deployed and a failing one rolls back", async () => {
  test.skip(!docker, "needs the agent with Docker");
  // Revision 2
  await page.getByRole("button", { name: "Edit" }).click();
  await page.getByLabel("compose.yaml").fill(stackCompose("echo app-v2; sleep 600"));
  await page.getByLabel("Change note").fill("second revision");
  await expect(page.getByText("Valid and allowed by the container policy.")).toBeVisible();
  await page.getByRole("button", { name: "Save and deploy" }).click();
  await expect(page.getByText(/deployed revision 2/)).toBeVisible({ timeout: 120_000 });

  // Revision 3: the app exits at once, so the deployment fails and rolls back to 2.
  await page.getByRole("button", { name: "Edit" }).click();
  await page.getByLabel("compose.yaml").fill(stackCompose("exit 3"));
  await page.getByLabel("Change note").fill("broken");
  await expect(page.getByText("Valid and allowed by the container policy.")).toBeVisible();
  await page.getByRole("button", { name: "Save and deploy" }).click();
  await expect(page.getByText(/deployment of revision 3 failed; rolled back to revision 2/)).toBeVisible({ timeout: 150_000 });
  await expect(page.getByText(/deployed revision 2/)).toBeVisible();
  await expect(page.getByRole("table", { name: "Services" }).getByText("running")).toHaveCount(2, { timeout: 30_000 });
});

test("AT-F03-05: take the stack down", async () => {
  test.skip(!docker, "needs the agent with Docker");
  await page.getByRole("button", { name: "Take down" }).click();
  await page.getByRole("dialog", { name: "Take down this stack?" }).getByRole("button", { name: "Take down" }).click();
  await waitStackStatus(page, "stopped");
  await page.getByRole("button", { name: "Delete" }).click();
  await expect(page.getByRole("heading", { name: "Stacks", exact: true })).toBeVisible();
});

// ---- M8: app store ----

const catalogKeys = generateKeyPairSync("ed25519");
const trustKey = catalogKeys.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");

function e2eApp(version: string, message: string) {
  return {
    id: "e2e-notes",
    name: "E2E Notes",
    version,
    summary: "A test app for the browser tests",
    categories: ["Testing"],
    compose: `services:
  app:
    image: alpine:3
    user: "65534"
    mem_limit: 64m
    command: ["sh", "-c", "echo ${message} \${TITLE}; sleep 600"]
    ports: ["127.0.0.1:\${PORT}:8080"]
    environment:
      TOKEN: \${TOKEN}
    healthcheck:
      test: ["CMD", "true"]
      interval: 1s
      retries: 3
    volumes: [data:/data]
volumes:
  data:
`,
    fields: [
      { name: "TITLE", label: "Title", type: "text", default: "notes" },
      { name: "PORT", label: "Port", type: "number", default: "18090", min: 1024, required: true },
      { name: "TOKEN", label: "Token", type: "password", generate: "hex32", required: true },
    ],
    web: { service: "app", port: 8080 },
    exceptions: [],
  };
}

function signedCatalog(serial: number, version: string, message: string): Buffer {
  const payload = Buffer.from(JSON.stringify({ name: "E2E catalog", serial, expires: new Date(Date.now() + 30 * 86400_000).toISOString(), apps: [e2eApp(version, message)] }));
  const signature = cryptoSign(null, Buffer.concat([Buffer.from("kernhaven-catalog/v1\n"), payload]), catalogKeys.privateKey);
  return Buffer.from(JSON.stringify({ format: "kernhaven-catalog/v1", key_id: "", payload: payload.toString("base64"), signature: signature.toString("base64") }));
}

async function uploadCatalog(p: Page, data: Buffer) {
  await p.goto("/apps/sources");
  await p.getByLabel("Upload catalog").setInputFiles({ name: "catalog.json", mimeType: "application/json", buffer: data });
  await expect(p.getByText("Catalog for E2E catalog verified and accepted.")).toBeVisible();
}

test("AT-F04-01, AT-F04-03: the owner adds a source and uploads a signed catalog", async () => {
  test.skip(!docker, "needs the agent with Docker");
  await page.goto("/apps/store");
  await expect(page.getByText("No apps found.")).toBeVisible();
  await page.getByRole("button", { name: "Manage sources" }).click();
  await page.getByRole("button", { name: "Add source" }).click();
  const dialog = page.getByRole("dialog", { name: "Add catalog source" });
  await dialog.getByLabel("Name").fill("E2E catalog");
  await dialog.getByLabel("Trust key").fill(trustKey);
  await dialog.getByRole("button", { name: "Add source" }).click();
  await expect(page.getByText("Source added.")).toBeVisible();
  // A tampered catalog is rejected and the reason is shown.
  const tampered = signedCatalog(1, "1.0", "v1").toString().replace(/"signature":"./, '"signature":"A');
  await page.getByLabel("Upload catalog").setInputFiles({ name: "bad.json", mimeType: "application/json", buffer: Buffer.from(tampered) });
  await expect(page.getByText(/Last catalog rejected: the catalog signature is not valid/)).toBeVisible();
  await uploadCatalog(page, signedCatalog(1, "1.0", "v1"));
  await expect(page.getByText(/serial 1 · 1 apps/)).toBeVisible();
  await expectAccessible(page, "catalog sources");
});

test("AT-F04-02, AT-F04-04, AT-F05-01: browse, review the disclosure and install", async () => {
  test.skip(!docker, "needs the agent with Docker");
  await page.goto("/apps/store");
  await page.getByLabel("Search apps").fill("e2e");
  await page.getByRole("button", { name: "Testing" }).click();
  await page.getByRole("link", { name: "E2E Notes" }).click();
  await expect(page.getByRole("heading", { name: "What this app can do" })).toBeVisible();
  await expect(page.getByText("127.0.0.1:18090 → 8080/tcp")).toBeVisible();
  await expect(page.getByText("image not pinned")).toBeVisible();
  await expectAccessible(page, "store app");
  await page.getByLabel("Name", { exact: true }).fill("e2e-app");
  await page.getByLabel("Title").fill("hello");
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page.getByRole("heading", { name: "e2e-app" })).toBeVisible();
  await expect(page.getByText("deployed", { exact: true })).toBeVisible({ timeout: 120_000 });
  await expect(page.getByRole("link", { name: "Open E2E Notes" })).toBeVisible();
  await expect(page.getByText("secret", { exact: true })).toBeVisible();
  await expectAccessible(page, "installed app");
});

test("AT-F05-02: update with a snapshot of the data", async () => {
  test.skip(!docker, "needs the agent with Docker");
  await uploadCatalog(page, signedCatalog(2, "2.0", "v2"));
  await page.goto("/apps/e2e-app");
  await expect(page.getByRole("heading", { name: "Update available: 1.0 → 2.0" })).toBeVisible();
  await page.getByRole("button", { name: "Review update" }).click();
  await page.getByRole("button", { name: "Update to 2.0" }).click();
  await expect(page.getByText(/Updating to 2.0/)).toBeVisible();
  await expect(page.getByText(/E2E Notes 2\.0 · from E2E catalog/)).toBeVisible({ timeout: 180_000 });
  await expect(page.getByRole("table", { name: "Versions" }).getByRole("row")).toHaveCount(3);
});

test("AT-F05-03: remove the app and its data (step-up, still fresh after sign-in)", async () => {
  test.skip(!docker, "needs the agent with Docker");
  await page.getByRole("button", { name: "Remove" }).click();
  const dialog = page.getByRole("dialog", { name: "Remove e2e-app?" });
  await dialog.getByLabel(/Delete the data permanently/).check();
  await dialog.getByRole("button", { name: "Remove app and data" }).click();
  await expect(page.getByRole("heading", { name: "Apps", exact: true })).toBeVisible();
  await expect(page.getByText("No apps installed yet.")).toBeVisible({ timeout: 120_000 });
});

test("AT-F06-01, TH-32: the storage page shows the real disks and finds the system disk", async () => {
  await page.goto("/storage");
  await expect(page.getByRole("heading", { name: "Storage", exact: true })).toBeVisible();
  await expect(page.getByText("system disk", { exact: true }).first()).toBeVisible();
  // Without root the storage service only reports; nothing can be formatted or mounted.
  await expect(page.getByText(/does not run as root/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Format…" })).toHaveCount(0);
  await expectAccessible(page, "storage");
});

test("AT-F07-01..05: file manager — folder, resumable upload, preview, rename, trash and restore", async () => {
  await page.goto("/files");
  await expect(page.getByRole("heading", { name: "Files", exact: true })).toBeVisible();
  await expect(page.getByText("This folder is empty.")).toBeVisible();
  await page.getByRole("button", { name: "New folder" }).click();
  const mk = page.getByRole("dialog", { name: "New folder" });
  await mk.getByLabel("Name").fill("docs");
  await mk.getByRole("button", { name: "Create" }).click();
  await page.getByRole("button", { name: "docs", exact: true }).click();
  await page.getByLabel("Upload").setInputFiles({ name: "note.txt", mimeType: "text/plain", buffer: Buffer.from("hello <b>e2e</b>") });
  await expect(page.getByRole("cell", { name: "note.txt", exact: true })).toBeVisible();
  // Previews are text, never HTML.
  await page.getByRole("button", { name: "View note.txt" }).click();
  const preview = page.getByRole("dialog", { name: "note.txt" });
  await expect(preview.getByText("hello <b>e2e</b>")).toBeVisible();
  await expectAccessible(page, "file preview");
  await preview.getByRole("button", { name: "Close" }).click();
  await expect(page.getByRole("link", { name: "Download note.txt" })).toHaveAttribute("href", /files\/download\?root=data&path=docs%2Fnote\.txt/);
  await page.getByRole("button", { name: "Rename note.txt" }).click();
  const rn = page.getByRole("dialog", { name: "Rename note.txt" });
  await rn.getByLabel("Name").fill("renamed.txt");
  await rn.getByRole("button", { name: "Rename" }).click();
  await page.getByRole("button", { name: "Delete renamed.txt" }).click();
  await page.getByRole("dialog", { name: "Delete renamed.txt?" }).getByRole("button", { name: "Move to trash" }).click();
  await expect(page.getByText("This folder is empty.")).toBeVisible();
  await page.getByRole("button", { name: "Trash" }).click();
  await expect(page.getByRole("cell", { name: "docs/renamed.txt", exact: true })).toBeVisible();
  await expectAccessible(page, "trash");
  await page.getByRole("button", { name: "Restore docs/renamed.txt" }).click();
  await expect(page.getByText("Restored docs/renamed.txt.")).toBeVisible();
  await page.getByRole("button", { name: "Back to files" }).click();
  await expect(page.getByRole("cell", { name: "renamed.txt", exact: true })).toBeVisible();
  await expectAccessible(page, "files");
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
    for (const path of ["/", "/jobs", "/users", "/audit", "/account", "/containers", "/containers/new", "/images", "/volumes", "/networks", "/stacks", "/stacks/new", "/apps", "/apps/store", "/apps/sources", "/storage", "/files", "/proxy", "/certificates"]) {
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
  await viewer.goto("/containers");
  await expect(viewer.getByRole("heading", { name: "Containers", exact: true })).toBeVisible();
  await expect(viewer.getByRole("button", { name: "New container" })).toHaveCount(0);
  // M9: viewers do not see disks.
  await expect(nav.getByRole("link", { name: "Storage" })).toHaveCount(0);
  await expect(nav.getByRole("link", { name: "Files" })).toHaveCount(0);
  // M12/M13: viewers do not see the reverse proxy or certificates.
  await expect(nav.getByRole("link", { name: "Reverse proxy" })).toHaveCount(0);
  await expect(nav.getByRole("link", { name: "Certificates" })).toHaveCount(0);
  // M8: viewers browse the store but cannot install or manage sources.
  await viewer.goto("/apps/sources");
  await expect(viewer.getByRole("heading", { name: "Catalog sources" })).toBeVisible();
  await expect(viewer.getByRole("button", { name: "Add source" })).toHaveCount(0);
  await viewer.context().close();
});

// ---- M11: runs last, because afterwards the owner has a second factor ----

function totp(secret: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secret.replace(/\s/g, "")) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000 / 30)));
  const h = createHmac("sha1", key).update(msg).digest();
  const o = h[19]! & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

const proxy = process.env.KH_E2E_PROXY === "1";
const appURL = "https://whoami.kh.test:18443/";

test("AT-F11-01..04, AT-F05-01: publish a route with Kernhaven sign-in through real Caddy", async () => {
  test.skip(!proxy, "needs Caddy (KH_E2E_CADDY)");
  await page.goto("/proxy");
  await expect(page.getByRole("heading", { name: "Reverse proxy" })).toBeVisible();
  await expect(page.getByText("running", { exact: true })).toBeVisible();
  await expect(page.getByRole("table", { name: "Network interfaces" })).toBeVisible();
  await expect(page.getByRole("table", { name: "Listening ports" }).getByRole("cell", { name: "18443", exact: true }).first()).toBeVisible();
  await expectAccessible(page, "reverse proxy");

  await page.getByRole("button", { name: "Add a route" }).click();
  const dialog = page.getByRole("dialog", { name: "Add a route" });
  await dialog.getByLabel("Host name").fill("whoami.kh.test");
  await dialog.getByLabel("Port on this server").fill("18490");
  await dialog.getByLabel("Require Kernhaven sign-in").check();
  await expectAccessible(page, "route dialog");
  await dialog.getByRole("button", { name: "Publish" }).click();
  await expect(page.getByText("whoami.kh.test is published.")).toBeVisible();
  await expect(page.getByText("configuration in sync")).toBeVisible();

  // The app's host sends the browser through the gate and back with its own cookie.
  const app = await page.context().newPage();
  await expect(async () => {
    await app.goto(appURL);
    await expect(app.getByText("hello from upstream")).toBeVisible({ timeout: 2_000 });
  }).toPass({ timeout: 20_000 });
  expect(new URL(app.url()).host).toBe("whoami.kh.test:18443");
  const cookies = await page.context().cookies(appURL);
  expect(cookies.find((c) => c.name.startsWith("kh_gate_"))?.httpOnly).toBe(true);

  // An allow-list without this client turns it away.
  await page.getByRole("button", { name: "Edit whoami.kh.test" }).click();
  const edit = page.getByRole("dialog", { name: "Edit whoami.kh.test" });
  await edit.getByLabel("Allowed networks (optional)").fill("10.0.0.0/8");
  await edit.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("whoami.kh.test was updated.")).toBeVisible();
  await app.goto(appURL);
  await expect(app.getByText("Forbidden")).toBeVisible();

  await page.getByRole("button", { name: "Delete whoami.kh.test" }).click();
  await page.getByRole("button", { name: "Delete route" }).click();
  await expect(page.getByText("whoami.kh.test was deleted.")).toBeVisible();
  // Without a route Caddy no longer serves the host at all (no certificate).
  const after = await app.goto(appURL).then(
    () => app.textContent("body"),
    () => "",
  );
  expect(after ?? "").not.toContain("hello from upstream");
  await app.close();
});

test("AT-F12-02, AT-F12-03: root download, upload and assign an own certificate", async () => {
  test.skip(!proxy || !process.env.KH_E2E_CERT_DIR, "needs Caddy and openssl");
  const dir = process.env.KH_E2E_CERT_DIR!;
  // A route for the host first.
  await page.goto("/proxy");
  await page.getByRole("button", { name: "Add a route" }).click();
  const routeDialog = page.getByRole("dialog", { name: "Add a route" });
  await routeDialog.getByLabel("Host name").fill("custom.kh.test");
  await routeDialog.getByLabel("Port on this server").fill("18490");
  await routeDialog.getByRole("button", { name: "Publish" }).click();
  await expect(page.getByText("custom.kh.test is published.")).toBeVisible();

  await page.goto("/certificates");
  await expect(page.getByRole("heading", { name: "Certificates", exact: true })).toBeVisible();
  await expect(page.getByText(/Check the fingerprint on the device/)).toBeVisible();
  const root = await page.request.get("/api/v1/tls/root.crt");
  expect(root.status()).toBe(200);
  expect(await root.text()).toContain("BEGIN CERTIFICATE");
  await expectAccessible(page, "certificates");

  await page.getByRole("button", { name: "Upload a certificate" }).click();
  const up = page.getByRole("dialog", { name: "Upload a certificate" });
  await up.getByLabel("Certificate file").setInputFiles(`${dir}/chain.pem`);
  await up.getByLabel("Key file").setInputFiles(`${dir}/leaf.key`);
  await expect(up.getByLabel(/Certificate chain/)).toHaveValue(/BEGIN CERTIFICATE/);
  await expect(up.getByLabel(/Private key/)).toHaveValue(/PRIVATE KEY/);
  await expectAccessible(page, "upload dialog");
  await up.getByRole("button", { name: "Upload" }).click();
  await expect(page.getByText(/The certificate for custom.kh.test was stored/)).toBeVisible();

  await page.getByRole("button", { name: "Change custom.kh.test" }).click();
  const hd = page.getByRole("dialog", { name: "Certificate for custom.kh.test" });
  await hd.getByLabel(/Own certificate/).check();
  await hd.getByRole("button", { name: "Apply" }).click();
  await expect(page.getByText("custom.kh.test uses Own certificate.")).toBeVisible();

  // Caddy now presents exactly the uploaded certificate for this host.
  const issuer = () =>
    new Promise<string>((resolve, reject) => {
      const s = connect({ host: "127.0.0.1", port: 18443, servername: "custom.kh.test", rejectUnauthorized: false }, () => {
        const cn = s.getPeerCertificate().issuer.CN;
        s.end();
        resolve(Array.isArray(cn) ? cn.join(",") : (cn ?? ""));
      });
      s.on("error", reject);
    });
  await expect(async () => expect(await issuer()).toBe("Kernhaven E2E Own CA")).toPass({ timeout: 10_000 });

  // Back to the internal CA; the certificate can then be deleted, and the route too.
  await page.getByRole("button", { name: "Change custom.kh.test" }).click();
  await hd.getByLabel(/Kernhaven CA/).check();
  await hd.getByRole("button", { name: "Apply" }).click();
  await expect(page.getByText("custom.kh.test uses Kernhaven CA.")).toBeVisible();
  await page.getByRole("button", { name: "Delete custom.kh.test" }).click();
  await expect(page.getByText("The certificate was deleted.")).toBeVisible();
  await page.goto("/proxy");
  await page.getByRole("button", { name: "Delete custom.kh.test" }).click();
  await page.getByRole("button", { name: "Delete route" }).click();
  await expect(page.getByText("custom.kh.test was deleted.")).toBeVisible();
});

test("AT-F09-02, AT-F09-03: authenticator app, recovery codes and passkey; sign in with them", async () => {
  // Chrome's virtual authenticator stands in for a platform passkey.
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });

  await page.goto("/account");
  await page.getByRole("button", { name: "Set up an authenticator app" }).click();
  const secret = (await page.getByLabel("Setup key").innerText()).trim();
  await page.getByLabel("Code from the app").fill(totp(secret));
  await page.getByRole("button", { name: "Turn on" }).click();
  await expect(page.getByRole("list", { name: "Recovery codes" }).getByRole("listitem")).toHaveCount(10);
  const recovery = (await page.getByRole("list", { name: "Recovery codes" }).getByRole("listitem").first().innerText()).trim();
  await page.getByRole("button", { name: "I saved them" }).click();

  await page.getByLabel("Passkey name").fill("E2E key");
  await page.getByRole("button", { name: "Add a passkey" }).click();
  await expect(page.getByText("The passkey was added.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Remove E2E key" })).toBeVisible();
  await expectAccessible(page, "account security");

  // Passkey alone.
  await page.getByRole("button", { name: "Sign out" }).first().click();
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  // Signing out on /account returns there after the sign-in (?next=/account).
  await expect(page).toHaveURL(/\/account$/);
  await expect(page.getByRole("heading", { name: "Account", exact: true })).toBeVisible();

  // Password, then a recovery code as second step.
  await page.getByRole("button", { name: "Sign out" }).first().click();
  await page.getByLabel("Username").fill(OWNER.username);
  await page.getByLabel("Password").fill(OWNER.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Confirm it is you" })).toBeVisible();
  await expectAccessible(page, "second factor");
  await page.getByRole("button", { name: "Use a recovery code instead" }).click();
  await page.getByLabel("Recovery code").fill(recovery);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page).toHaveURL(/\/account$/);
  await expect(page.getByRole("heading", { name: "Account", exact: true })).toBeVisible();
});
