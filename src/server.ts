/**
 * Lab server entry point.
 *
 * Runs the deliberately vulnerable lab endpoints. Before it binds anything, it
 * consults `evaluateBind`, which refuses non-loopback addresses unless the
 * operator explicitly acknowledges the exposure.
 *
 * Start with:  npm start
 */

import { createServer } from "node:http";
import { evaluateBind, exposureWarning } from "./config.ts";
import { handleRequest } from "./router.ts";

function main(): void {
  const decision = evaluateBind();

  if (!decision.allowed) {
    // Exit non-zero rather than starting in a degraded state. A refusal must
    // never be something you can scroll past.
    console.error(`\n[lab-server] STARTUP REFUSED\n\n${decision.reason}\n`);
    process.exitCode = 1;
    return;
  }

  const warning = exposureWarning(decision.host);
  if (warning !== "") {
    console.warn(warning);
  }

  const server = createServer((req, res) => {
    void handleRequest(req, res);
  });

  server.listen(decision.port, decision.host, () => {
    console.log(`[lab-server] listening on http://${decision.host}:${decision.port}`);
    console.log("[lab-server] these endpoints are intentionally vulnerable");
    console.log("[lab-server] press Ctrl+C to stop");
  });

  const shutdown = (signal: string): void => {
    console.log(`\n[lab-server] ${signal} received, closing`);
    server.close(() => process.exit(0));
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

main();