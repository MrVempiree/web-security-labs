/**
 * Safety tests.
 *
 * These are the most important tests in the project. They assert the property
 * that makes shipping deliberately vulnerable code acceptable: the vulnerable
 * endpoints cannot be reached from the network by default.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_HOST,
  DEFAULT_PORT,
  evaluateBind,
  exposureWarning,
  OVERRIDE_ENV_VAR,
} from "../src/config.ts";
import { ROUTE_PATHS } from "../src/router.ts";

/** Build an env object for tests without touching the real process env. */
function env(values: Record<string, string | undefined>): NodeJS.ProcessEnv {
  return values as NodeJS.ProcessEnv;
}

test("the default bind address is loopback, not 0.0.0.0", () => {
  assert.equal(DEFAULT_HOST, "127.0.0.1");
});

test("an empty environment binds to loopback on the default port", () => {
  const decision = evaluateBind(env({}));
  assert.equal(decision.allowed, true);
  assert.equal(decision.allowed && decision.host, "127.0.0.1");
  assert.equal(decision.allowed && decision.port, DEFAULT_PORT);
});

test("explicit loopback hosts are permitted", () => {
  for (const host of ["127.0.0.1", "localhost", "::1"]) {
    const decision = evaluateBind(env({ HOST: host }));
    assert.equal(decision.allowed, true, `${host} should be permitted`);
  }
});

test("a wildcard bind is REFUSED by default", () => {
  const decision = evaluateBind(env({ HOST: "0.0.0.0" }));

  assert.equal(decision.allowed, false);
  assert.equal(decision.allowed === false ? decision.host : null, "0.0.0.0");
  assert.ok(decision.allowed === false && decision.reason.includes("Refusing"));
});

test("an arbitrary LAN address is REFUSED by default", () => {
  const decision = evaluateBind(env({ HOST: "192.168.1.50" }));
  assert.equal(decision.allowed, false);
});

test("the refusal names the override variable so the fix is discoverable", () => {
  const decision = evaluateBind(env({ HOST: "0.0.0.0" }));
  assert.ok(decision.allowed === false && decision.reason.includes(OVERRIDE_ENV_VAR));
});

test("a non-loopback bind requires explicit acknowledgement", () => {
  const decision = evaluateBind(
    env({ HOST: "0.0.0.0", [OVERRIDE_ENV_VAR]: "1" }),
  );
  assert.equal(decision.allowed, true);
});

test("an override value other than exactly '1' is not honoured", () => {
  for (const value of ["0", "true", "yes", ""]) {
    const decision = evaluateBind(
      env({ HOST: "0.0.0.0", [OVERRIDE_ENV_VAR]: value }),
    );
    assert.equal(decision.allowed, false, `override "${value}" must not be accepted`);
  }
});

test("an invalid port is rejected rather than silently coerced", () => {
  for (const port of ["0", "70000", "-1", "not-a-port"]) {
    assert.throws(
      () => evaluateBind(env({ PORT: port })),
      /PORT must be an integer/,
      `PORT="${port}" should have been rejected`,
    );
  }
});

test("a valid port is honoured", () => {
  const decision = evaluateBind(env({ PORT: "9100" }));
  assert.equal(decision.allowed && decision.port, 9100);
});

test("a warning is emitted for non-loopback binds and not for loopback", () => {
  assert.equal(exposureWarning("127.0.0.1"), "");
  assert.notEqual(exposureWarning("0.0.0.0"), "");
  assert.ok(exposureWarning("0.0.0.0").includes("WARNING"));
});

test("every registered route is non-empty and lowercase", () => {
  assert.ok(ROUTE_PATHS.length > 0);
  for (const path of ROUTE_PATHS) {
    assert.ok(path.startsWith("/"));
    assert.equal(path, path.toLowerCase());
  }
});

test("no route is accidentally mounted at the server root path twice", () => {
  const unique = new Set(ROUTE_PATHS);
  assert.equal(unique.size, ROUTE_PATHS.length);
});