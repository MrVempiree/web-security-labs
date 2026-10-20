/**
 * Minimal HTTP routing for the lab server.
 *
 * Deliberately dependency-free: `node:http` only. A security teaching tool
 * should not ask you to trust a 200-package dependency tree before it will run.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import {
  renderGreetingSecure,
  renderProfileSecure,
  renderProfileVulnerable,
  renderScriptEscaped,
  renderScriptVulnerable,
  renderTooltipSecure,
  renderTooltipVulnerable,
} from "./labs/xss.ts";
import { queryUsersSecure, queryUsersVulnerable } from "./labs/sqli.ts";
import {
  readNoteSecure,
  readNoteVulnerable,
  SESSIONS,
  type Session,
} from "./labs/brokenAccessControl.ts";

export type RouteResult = {
  readonly status: number;
  readonly contentType: string;
  readonly body: string;
};

type Handler = (
  url: URL,
  req: IncomingMessage,
) => RouteResult | Promise<RouteResult>;

function html(status: number, body: string): RouteResult {
  return {
    status,
    contentType: "text/html; charset=utf-8",
    body,
  };
}

function json(status: number, value: unknown): RouteResult {
  return {
    status,
    contentType: "application/json; charset=utf-8",
    body: JSON.stringify(value, null, 2),
  };
}

/** Resolve a demo session from the `?as=` query parameter. */
function sessionFrom(url: URL): Session | null {
  const requested = url.searchParams.get("as");
  if (requested === null) return null;
  return SESSIONS[requested] ?? null;
}

const ROUTES: Readonly<Record<string, Handler>> = {
  "/": () =>
    html(
      200,
      `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Web Security Labs</title></head><body>
<h1>Web Security Labs</h1>
<p>Deliberately vulnerable endpoints. Localhost only.</p>
<h2>Labs</h2>
<ul>
  <li><a href="/xss/vulnerable?bio=%3Cscript%3Ealert(1)%3C%2Fscript%3E">/xss/vulnerable</a></li>
  <li><a href="/xss/secure?bio=%3Cscript%3Ealert(1)%3C%2Fscript%3E">/xss/secure</a></li>
  <li><a href="/xss/tooltip/vulnerable?bio=%22%20onmouseover=%22alert(1)">/xss/tooltip/vulnerable</a></li>
  <li><a href="/xss/tooltip/secure?bio=%22%20onmouseover=%22alert(1)">/xss/tooltip/secure</a></li>
  <li><a href="/sqli/vulnerable?name=%27%20OR%20%271%27%3D%271">/sqli/vulnerable</a></li>
  <li><a href="/sqli/secure?name=%27%20OR%20%271%27%3D%271">/sqli/secure</a></li>
  <li><a href="/idor/vulnerable?id=102&amp;as=alice">/idor/vulnerable (alice -&gt; bob's note)</a></li>
  <li><a href="/idor/secure?id=102&amp;as=alice">/idor/secure (alice -&gt; bob's note)</a></li>
</ul>
</body></html>`,
    ),

  "/xss/vulnerable": (url) =>
    html(
      200,
      renderProfileVulnerable(
        "demo",
        url.searchParams.get("bio") ?? "",
      ).html,
    ),

  "/xss/secure": (url) =>
    html(
      200,
      renderProfileSecure("demo", url.searchParams.get("bio") ?? "").html,
    ),

  "/xss/greeting": (url) =>
    html(200, renderGreetingSecure(url.searchParams.get("name") ?? "").html),

  "/xss/tooltip/vulnerable": (url) =>
    html(200, renderTooltipVulnerable(url.searchParams.get("bio") ?? "").html),

  "/xss/tooltip/secure": (url) =>
    html(200, renderTooltipSecure(url.searchParams.get("bio") ?? "").html),

  "/xss/script/vulnerable": (url) =>
    html(200, renderScriptVulnerable(url.searchParams.get("name") ?? "").html),

  "/xss/script/secure": (url) =>
    html(200, renderScriptEscaped(url.searchParams.get("name") ?? "").html),

  "/sqli/vulnerable": (url) =>
    json(200, queryUsersVulnerable(url.searchParams.get("name") ?? "")),

  "/sqli/secure": (url) =>
    json(200, queryUsersSecure(url.searchParams.get("name") ?? "")),

  "/idor/vulnerable": (url) => {
    const id = Number.parseInt(url.searchParams.get("id") ?? "", 10);
    if (!Number.isInteger(id)) {
      return json(400, { error: "id must be an integer" });
    }
    const result = readNoteVulnerable(sessionFrom(url), id);
    return json(result.status, result);
  },

  "/idor/secure": (url) => {
    const id = Number.parseInt(url.searchParams.get("id") ?? "", 10);
    if (!Number.isInteger(id)) {
      return json(400, { error: "id must be an integer" });
    }
    const result = readNoteSecure(sessionFrom(url), id);
    return json(result.status, result);
  },

  "/healthz": () => json(200, { status: "ok" }),
};

export async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const host = req.headers.host ?? "127.0.0.1";
  let url: URL;
  try {
    url = new URL(req.url ?? "/", `http://${host}`);
  } catch {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "malformed request URL" }));
    return;
  }

  const handler = ROUTES[url.pathname];
  if (handler === undefined) {
    const result = json(404, { error: "not found", path: url.pathname });
    res.writeHead(result.status, { "content-type": result.contentType });
    res.end(result.body);
    return;
  }

  try {
    const result = await handler(url, req);
    // Defensive headers. Note this does NOT make the XSS routes safe — the
    // point of those routes is to demonstrate an unsafe response.
    res.writeHead(result.status, {
      "content-type": result.contentType,
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "cache-control": "no-store",
    });
    res.end(result.body);
  } catch (error: unknown) {
    // Errors must not leak stack traces to the client.
    const result = json(500, { error: "internal error" });
    res.writeHead(result.status, { "content-type": result.contentType });
    res.end(result.body);
    if (error instanceof Error) {
      console.error("[lab-server] unhandled error:", error.message);
    }
  }
}

export const ROUTE_PATHS: readonly string[] = Object.keys(ROUTES).sort();