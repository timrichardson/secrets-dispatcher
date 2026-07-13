import { expect, test } from "@playwright/test";
import { startTestBackend, type TestBackend } from "./fixtures/test-utils.mts";

let backend: TestBackend;

test.beforeAll(async () => {
  backend = await startTestBackend();
});

test.afterAll(async () => {
  await backend.cleanup();
});

function bitwardenRequest(id: string) {
  const now = new Date().toISOString();
  return {
    id,
    client: "local",
    items: [{
      path: "/org/freedesktop/secrets/collection/login/87",
      label: "org.freedesktop.Secret.Generic",
      attributes: {
        service: "Bitwarden",
        account: "573d16e3-f086-460d-a51e-aab700758698_accessTokenKey",
      },
    }],
    session: "/org/freedesktop/secrets/session/1",
    created_at: now,
    expires_at: new Date(Date.now() + 300_000).toISOString(),
    type: "get_secret",
    sender_info: {
      sender: ":1.100",
      pid: 246800,
      uid: 1000,
      user_name: "tim",
      invoker_name: "bitwarden-app",
      process_chain: [
        { name: "bitwarden-app", pid: 246800, exe: "/opt/Bitwarden/bitwarden-app" },
        { name: "bitwarden", pid: 246791, exe: "/opt/Bitwarden/bitwarden" },
        { name: "gnome-shell", pid: 18430, exe: "/usr/bin/gnome-shell" },
        { name: "systemd", pid: 13426, exe: "/usr/lib/systemd/systemd" },
      ],
    },
  };
}

test("pending and history use the notification-style request summary", async ({ page }) => {
  await page.routeWebSocket("**/api/v1/ws", (ws) => {
    const server = ws.connectToServer();
    server.onMessage((message) => {
      if (typeof message === "string") {
        const parsed = JSON.parse(message);
        if (parsed.type === "snapshot") {
          parsed.requests = [bitwardenRequest("pending-bitwarden")];
          parsed.history = [{
            request: bitwardenRequest("history-bitwarden"),
            resolution: "approved",
            resolved_at: new Date().toISOString(),
          }];
          ws.send(JSON.stringify(parsed));
          return;
        }
      }
      ws.send(message);
    });
  });

  await page.goto(await backend.generateLoginURL());

  const summaries = page.locator(".request-overview");
  await expect(summaries).toHaveCount(2);

  for (const summary of [summaries.nth(0), summaries.nth(1)]) {
    const rows = summary.locator(".overview-row");
    await expect(rows).toHaveCount(4);
    await expect(rows.nth(0).locator(".overview-label")).toHaveText("Application");
    await expect(rows.nth(0).locator(".overview-value")).toHaveText("bitwarden-app");
    await expect(rows.nth(1).locator(".overview-label")).toHaveText("Request");
    await expect(rows.nth(1).locator(".overview-value")).toHaveText("Read secret");
    await expect(rows.nth(2).locator(".overview-label")).toHaveText("Secret");
    await expect(rows.nth(2).locator(".overview-value")).toHaveText("Bitwarden — access token (account 573d16e3…)");
    await expect(rows.nth(3).locator(".overview-label")).toHaveText("Process");
    await expect(rows.nth(3).locator("summary")).toContainText("bitwarden-app");
    await expect(rows.nth(3).locator("summary")).toContainText("bitwarden");
    await expect(rows.nth(3).locator("summary")).toContainText("systemd");
  }
});
