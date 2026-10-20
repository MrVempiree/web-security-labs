/**
 * Runtime configuration for the labs.
 *
 * SAFETY DESIGN NOTE
 * ------------------
 * These labs ship deliberately vulnerable code. The single most important
 * property of this project is that the vulnerable code cannot be reached from
 * a network that is not the developer's own machine.
 *
 * Two mechanisms enforce that:
 *
 *  1. The default bind address is the IPv4 loopback address (127.0.0.1),
 *     NOT 0.0.0.0. Binding 0.0.0.0 would expose intentionally vulnerable
 *     endpoints to the local network.
 *
 *  2. A non-loopback bind address is refused unless the operator sets
 *     ALLOW_NON_LOOPBACK_BIND=1. That is a deliberate speed bump: you have
 *     to type the exact acknowledgement that you understand what you are
 *     doing before the server will listen on a routable interface.
 *
 * LIMITATION (stated deliberately, not hidden):
 * Binding to loopback reduces exposure. It does not make the labs safe to run
 * on a shared machine, on a VPS, in a container with a published port, or
 * behind a reverse proxy that forwards to it. Do not deploy these labs
 * anywhere. See SECURITY.md.
 */

/** Address used unless explicitly overridden. Loopback only. */
export const DEFAULT_HOST = "127.0.0.1";

/** Default port. High and unprivileged to reduce accidental collisions. */
export const DEFAULT_PORT = 8080;

/** Interface names that are considered safe to bind without acknowledgement. */
const LOOPBACK_ADDRESSES: ReadonlySet<string> = new Set([
  "127.0.0.1",
  "localhost",
  "::1",
]);

/** Environment variable a user must set to escape the loopback default. */
export const OVERRIDE_ENV_VAR = "ALLOW_NON_LOOPBACK_BIND";

export type BindDecision =
  | { readonly allowed: true; readonly host: string; readonly port: number }
  | {
      readonly allowed: false;
      readonly reason: string;
      readonly host: string;
      readonly port: number;
    };

function parsePort(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === "") return DEFAULT_PORT;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(
      `PORT must be an integer between 1 and 65535, received: ${raw}`,
    );
  }
  return parsed;
}

/**
 * Decide whether the server is permitted to bind to the requested address.
 *
 * Returns a decision object rather than throwing so the caller can present a
 * clear, actionable message. A refusal is always explained.
 */
export function evaluateBind(
  env: NodeJS.ProcessEnv = process.env,
): BindDecision {
  const host = env.HOST?.trim() || DEFAULT_HOST;
  const port = parsePort(env.PORT);
  const override = env[OVERRIDE_ENV_VAR];

  if (LOOPBACK_ADDRESSES.has(host)) {
    return { allowed: true, host, port };
  }

  if (override === "1") {
    return { allowed: true, host, port };
  }

  return {
    allowed: false,
    host,
    port,
    reason:
      `Refusing to bind to non-loopback address "${host}".\n` +
      `This server hosts intentionally vulnerable endpoints and must not be ` +
      `reachable from the network.\n` +
      `Use 127.0.0.1, or set ${OVERRIDE_ENV_VAR}=1 if you genuinely understand ` +
      `the exposure you are creating.`,
  };
}

/**
 * Human-readable warning printed once at startup.
 * Kept separate so tests can assert on the policy without capturing stdout.
 */
export function exposureWarning(host: string): string {
  if (LOOPBACK_ADDRESSES.has(host)) return "";
  return (
    `\n  WARNING: listening on ${host}, which is reachable off-machine.\n` +
    `  These labs contain deliberately vulnerable code. Do not expose this\n` +
    `  server to an untrusted network.\n`
  );
}