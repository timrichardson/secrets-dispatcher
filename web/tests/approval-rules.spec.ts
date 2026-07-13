import { expect, test } from "@playwright/test";
import { startTestBackend, type TestBackend } from "./fixtures/test-utils.mts";

let backend: TestBackend;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  backend = await startTestBackend();
});

test.afterAll(async () => {
  await backend.cleanup();
});

function authHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

function savedRulePayload(name: string) {
  return {
    name,
    enabled: true,
    request_types: ["get_secret"],
    process: { unit: `${name}-process` },
    secret: {
      collection: "login",
      attributes: { service: name },
    },
  };
}

async function createSavedRule(token: string, name: string): Promise<string> {
  const response = await fetch(`${backend.url}/api/v1/approval-rules`, {
    method: "POST",
    headers: authHeaders(token),
    body: JSON.stringify(savedRulePayload(name)),
  });
  expect(response.status).toBe(200);
  const data = await response.json() as { id: string };
  return data.id;
}

async function injectHistoryEntry(
  token: string,
  requestId: string,
  unitName: string,
): Promise<void> {
  const now = new Date().toISOString();
  const response = await fetch(`${backend.url}/api/v1/test/history`, {
    method: "POST",
    headers: authHeaders(token),
    body: JSON.stringify({
      request: {
        id: requestId,
        client: "test-client",
        items: [
          {
            path: "/org/freedesktop/secrets/collection/login/item1",
            label: "GitHub token",
            attributes: { service: "github" },
          },
        ],
        session: "/org/freedesktop/secrets/session/1",
        created_at: now,
        expires_at: now,
        type: "get_secret",
        sender_info: {
          sender: ":1.42",
          pid: 4242,
          uid: 1000,
          user_name: "testuser",
          invoker_name: unitName,
          systemd_unit: `${unitName}.service`,
          process_chain: [
            {
              name: unitName,
              pid: 4242,
              exe: `/usr/bin/${unitName}`,
            },
          ],
        },
      },
      resolution: "cancelled",
      resolved_at: now,
    }),
  });
  expect(response.status).toBe(200);
}

test.describe("Saved Approval Rules WebSocket", () => {
  test("snapshot includes approval_rules field", async ({ page }) => {
    let snapshotMsg: Record<string, unknown> | null = null;

    await page.routeWebSocket(`**/api/v1/ws`, (ws) => {
      const server = ws.connectToServer();
      server.onMessage((message) => {
        if (typeof message === "string") {
          try {
            const parsed = JSON.parse(message);
            if (parsed.type === "snapshot") {
              snapshotMsg = parsed;
            }
          } catch { /* not JSON */ }
        }
        ws.send(message);
      });
    });

    await page.goto(await backend.generateLoginURL());
    await expect(page.getByText("No pending requests")).toBeVisible();

    expect(snapshotMsg).not.toBeNull();
    expect(snapshotMsg).toHaveProperty("approval_rules");
    expect(Array.isArray(snapshotMsg!.approval_rules)).toBe(true);
  });

  test("saved rules from snapshot render in approval rules section", async ({ page }) => {
    const now = new Date().toISOString();

    await page.routeWebSocket(`**/api/v1/ws`, (ws) => {
      const server = ws.connectToServer();
      server.onMessage((message) => {
        if (typeof message === "string") {
          try {
            const parsed = JSON.parse(message);
            if (parsed.type === "snapshot") {
              parsed.auto_approve_rules = [];
              parsed.approval_rules = [
                {
                  id: "saved-snapshot-rule",
                  name: "Snapshot saved rule",
                  enabled: true,
                  request_types: ["get_secret"],
                  process: { unit: "snapshot-invoker" },
                  secret: {
                    collection: "login",
                    attributes: { service: "github" },
                  },
                  created_at: now,
                  updated_at: now,
                },
              ];
              ws.send(JSON.stringify(parsed));
              return;
            }
          } catch { /* not JSON */ }
        }
        ws.send(message);
      });
    });

    await page.goto(await backend.generateLoginURL());
    const section = page.locator("#approval-rules");
    await expect(section.getByText("Approval Rules")).toBeVisible({
      timeout: 10000,
    });
    await section.getByRole("button").first().click();

    await expect(section.getByText("Snapshot saved rule")).toBeVisible();
    await expect(section.getByText("snapshot-invoker")).toBeVisible();
    await expect(section.getByText("login")).toBeVisible();
    await expect(section.getByText("github")).toBeVisible();
  });
});

test.describe("Saved Approval Rules UI", () => {
  test("persisting a temporary rule moves it to saved rules", async ({ page }) => {
    const token = await backend.getAuthToken();
    await injectHistoryEntry(token, "persist-source", "persist-invoker");

    const createTemp = await fetch(`${backend.url}/api/v1/auto-approve`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ request_id: "persist-source" }),
    });
    expect(createTemp.status).toBe(200);

    await page.goto(await backend.generateLoginURL());
    const section = page.locator("#approval-rules");
    await section.getByRole("button").first().click();

    const temporary = section.locator(".rules-subsection").first();
    const saved = section.locator(".rules-subsection").nth(1);
    await expect(temporary.getByText("persist-invoker")).toBeVisible({
      timeout: 10000,
    });
    await temporary.getByRole("button", { name: "Save" }).click();

    await expect(temporary.getByText("persist-invoker")).not.toBeVisible();
    await expect(saved.getByText("persist-invoker get_secret")).toBeVisible();
    await expect(saved.getByRole("cell", { name: "/usr/bin/persist-invoker" }))
      .toBeVisible();
  });

  test("saved rule can be disabled, enabled, and deleted", async ({ page }) => {
    const token = await backend.getAuthToken();
    await createSavedRule(token, "ui-managed-rule");

    await page.goto(await backend.generateLoginURL());
    const section = page.locator("#approval-rules");
    await section.getByRole("button").first().click();

    const row = section.locator(".rule-entry").filter({
      hasText: "ui-managed-rule",
    });
    await expect(row).toBeVisible({ timeout: 10000 });

    await row.getByRole("button", { name: "Disable" }).click();
    await expect(row.getByText("disabled")).toBeVisible();

    await row.getByRole("button", { name: "Enable" }).click();
    await expect(row.getByText("saved")).toBeVisible();

    await row.getByTitle("Delete saved rule").click();
    await expect(row).not.toBeVisible();
  });

  test("save rule from pending request calls API without resolving request", async ({ page }) => {
    const now = new Date().toISOString();
    let postedRequestID = "";

    await page.route("**/api/v1/approval-rules/from-request", async (route) => {
      const body = route.request().postDataJSON() as { request_id: string };
      postedRequestID = body.request_id;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          id: "pending-saved-rule",
          name: "Pending saved rule",
          enabled: true,
          request_types: ["get_secret"],
          process: { unit: "pending-invoker" },
          secret: { collection: "login" },
          created_at: now,
          updated_at: now,
        }),
      });
    });

    await page.routeWebSocket(`**/api/v1/ws`, (ws) => {
      const server = ws.connectToServer();
      server.onMessage((message) => {
        if (typeof message === "string") {
          try {
            const parsed = JSON.parse(message);
            if (parsed.type === "snapshot") {
              parsed.requests = [
                {
                  id: "pending-save-source",
                  client: "test-client",
                  items: [
                    {
                      path: "/org/freedesktop/secrets/collection/login/item2",
                      label: "Pending token",
                      attributes: { service: "pending" },
                    },
                  ],
                  session: "/org/freedesktop/secrets/session/2",
                  created_at: now,
                  expires_at: new Date(Date.now() + 300_000).toISOString(),
                  type: "get_secret",
                  sender_info: {
                    sender: ":1.55",
                    pid: 5555,
                    uid: 1000,
                    user_name: "testuser",
                    invoker_name: "pending-invoker",
                    systemd_unit: "pending-invoker.service",
                  },
                },
              ];
              parsed.approval_rules = [];
              parsed.auto_approve_rules = [];
              ws.send(JSON.stringify(parsed));
              return;
            }
          } catch { /* not JSON */ }
        }
        ws.send(message);
      });
    });

    await page.goto(await backend.generateLoginURL());

    const card = page.locator(".card--get_secret");
    await expect(card.locator(".item-summary")).toContainText("Pending token", {
      timeout: 10000,
    });
    await card.getByRole("button", { name: "Save rule" }).click();

    await expect.poll(() => postedRequestID).toBe("pending-save-source");
    await expect(card.locator(".item-summary")).toContainText("Pending token");
    await expect(card.getByRole("button", { name: "Approve", exact: true }))
      .toBeVisible();
  });

  test("recent history shows saved rule attribution", async ({ page }) => {
    const now = new Date().toISOString();

    await page.routeWebSocket(`**/api/v1/ws`, (ws) => {
      const server = ws.connectToServer();
      server.onMessage((message) => {
        if (typeof message === "string") {
          try {
            const parsed = JSON.parse(message);
            if (parsed.type === "snapshot") {
              parsed.history = [
                {
                  request: {
                    id: "saved-rule-history",
                    client: "test-client",
                    items: [
                      {
                        path: "/org/freedesktop/secrets/collection/login/item3",
                        label: "Saved rule token",
                        attributes: { service: "github" },
                      },
                    ],
                    session: "/org/freedesktop/secrets/session/3",
                    created_at: now,
                    expires_at: now,
                    type: "get_secret",
                    sender_info: {
                      sender: ":1.66",
                      pid: 6666,
                      uid: 1000,
                      user_name: "testuser",
                      unit_name: "history-invoker",
                    },
                    attribution: {
                      source: "saved_rule",
                      rule_id: "rule-history-123456",
                      rule_name: "History saved rule",
                      rule_request_types: ["get_secret"],
                      process: { unit: "history-invoker" },
                      secret: { collection: "login" },
                    },
                  },
                  resolution: "auto_approved",
                  resolved_at: now,
                },
              ];
              ws.send(JSON.stringify(parsed));
              return;
            }
          } catch { /* not JSON */ }
        }
        ws.send(message);
      });
    });

    await page.goto(await backend.generateLoginURL());

    await expect(page.getByText("Recent Activity")).toBeVisible({
      timeout: 10000,
    });
    await expect(page.getByText("Saved rule token")).toBeVisible();
    await expect(
      page.getByText(
        "Auto-approved by saved rule: History saved rule (rule-his)",
      ),
    ).toBeVisible();
  });

  test("recent history shows denied config rule attribution", async ({ page }) => {
    const now = new Date().toISOString();

    await page.routeWebSocket(`**/api/v1/ws`, (ws) => {
      const server = ws.connectToServer();
      server.onMessage((message) => {
        if (typeof message === "string") {
          try {
            const parsed = JSON.parse(message);
            if (parsed.type === "snapshot") {
              parsed.history = [
                {
                  request: {
                    id: "config-rule-denied-history",
                    client: "test-client",
                    items: [
                      {
                        path: "/org/freedesktop/secrets/collection/login/item4",
                        label: "Denied rule token",
                        attributes: { service: "browser" },
                      },
                    ],
                    session: "/org/freedesktop/secrets/session/4",
                    created_at: now,
                    expires_at: now,
                    type: "get_secret",
                    sender_info: {
                      sender: ":1.77",
                      pid: 7777,
                      uid: 1000,
                      user_name: "testuser",
                      unit_name: "denied-invoker",
                    },
                    attribution: {
                      source: "config_rule",
                      action: "deny",
                      rule_name: "Deny browser tokens",
                      rule_request_types: ["get_secret"],
                      process: { unit: "denied-invoker" },
                      secret: { collection: "login" },
                    },
                  },
                  resolution: "denied",
                  resolved_at: now,
                },
              ];
              ws.send(JSON.stringify(parsed));
              return;
            }
          } catch { /* not JSON */ }
        }
        ws.send(message);
      });
    });

    await page.goto(await backend.generateLoginURL());

    await expect(page.getByText("Recent Activity")).toBeVisible({
      timeout: 10000,
    });
    await expect(page.getByText("Denied rule token")).toBeVisible();
    await expect(
      page.getByText("Denied by config rule: Deny browser tokens"),
    ).toBeVisible();
  });
});
