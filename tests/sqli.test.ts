/**
 * Lab 2 tests — SQL Injection.
 *
 * The vulnerable and secure query builders are driven with identical payloads
 * so the structural difference is demonstrated, not asserted.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  bind,
  isAuthenticationBypass,
  queryUsersSecure,
  queryUsersVulnerable,
  runQuery,
  SQLI_PAYLOADS,
  stripComment,
} from "../src/labs/sqli.ts";
import {
  parameterCount,
  parametersMatch,
  placeholderCount,
  prepare,
} from "../src/security.ts";

test("the evaluator handles a plain equality query", () => {
  const rows = runQuery("SELECT * FROM users WHERE username = 'alice'", [
    { username: "alice" },
    { username: "bob" },
  ]);
  assert.equal(rows.length, 1);
});

test("the evaluator honours AND before OR, as SQL does", () => {
  const rows = runQuery(
    "SELECT * FROM users WHERE username = 'bob' OR username = 'alice' AND id = '999'",
    [
      { username: "alice", id: 1 },
      { username: "bob", id: 2 },
    ],
  );
  // AND binds tighter: (bob) OR (alice AND id=999) -> just bob.
  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.username, "bob");
});

test("the evaluator rejects statements it does not support", () => {
  assert.throws(() => runQuery("DROP TABLE users", []), /Unsupported statement/);
});

test("stripComment removes an unquoted trailing comment", () => {
  assert.equal(stripComment("username = 'alice'--"), "username = 'alice'");
  assert.equal(stripComment("username = 'alice' # note"), "username = 'alice'");
});

test("stripComment strips '--' that follows a CLOSED quote", () => {
  // 'alice' is a complete literal, so the '--' that follows it really is a
  // comment. This is why "alice'--" truncates the clause in the lab.
  assert.equal(stripComment("username = 'alice'--"), "username = 'alice'");
  assert.equal(stripComment("username = 'alice'--'"), "username = 'alice'");
});

test("stripComment does NOT strip a '--' inside an OPEN quote", () => {
  // The quote is still open here, so this is literal data, not a comment.
  assert.equal(stripComment("username = 'ali--ce'"), "username = 'ali--ce'");
});

test("VULNERABLE: a tautology returns every user", () => {
  const payload = "' OR '1'='1";
  const result = queryUsersVulnerable(payload);

  assert.equal(result.rowCount, 3);
  assert.ok(isAuthenticationBypass(result, payload));
  // The payload really did become syntax.
  assert.equal(result.sql, "SELECT * FROM users WHERE username = '' OR '1'='1'");
});

test("VULNERABLE: a prefixed tautology also returns every user", () => {
  const payload = "x' OR '1'='1";
  assert.equal(queryUsersVulnerable(payload).rowCount, 3);
});

test("VULNERABLE: comment truncation logs the attacker in as alice", () => {
  const payload = "alice'--";
  const result = queryUsersVulnerable(payload);

  // The comment kills the closing quote, so the clause becomes a plain match.
  assert.equal(result.rowCount, 1);
  assert.equal(result.rows[0]?.username, "alice");
  assert.ok(isAuthenticationBypass(result, payload));
});

test("a UNION payload is rejected as unsupported syntax, not evaluated", () => {
  // Stated explicitly because it is a real limitation of this toy engine: it
  // supports one statement shape, so a UNION payload is refused outright
  // rather than producing a second result set. Do not read this as "UNION is
  // not an injection technique" — it is, against a real database.
  const payload = "' UNION SELECT * FROM users --";
  assert.throws(
    () => queryUsersVulnerable(payload),
    /Unsupported operand/,
    "the evaluator should refuse a UNION payload rather than evaluate it",
  );
});

test("the secure query treats a UNION payload as an inert literal", () => {
  // Behaviour differs from the vulnerable path here, but NOT because
  // parameterisation blocked a UNION. It is because the bound value never
  // becomes syntax: the comment inside it is inside an open quote, so it is
  // stripped as data and the clause degrades to a literal comparison.
  // Against a real database the secure query would likewise match zero rows.
  const payload = "' UNION SELECT * FROM users --";
  const result = queryUsersSecure(payload);
  assert.equal(result.rowCount, 0);
});

test("a bare numeric tautology is evaluated, not rejected", () => {
  // Real SQL permits unquoted numbers; the engine must too, or the canonical
  // `' OR 1=1 --` payload could not be demonstrated.
  const payload = "' OR 1=1 --";
  assert.equal(queryUsersVulnerable(payload).rowCount, 3);
  assert.equal(queryUsersSecure(payload).rowCount, 0);
});

test("SECURE: the same tautology matches nothing", () => {
  const payload = "' OR '1'='1";
  const result = queryUsersSecure(payload);

  assert.equal(result.rowCount, 0);
  assert.equal(isAuthenticationBypass(result, payload), false);
});

test("SECURE: the payload is bound as a literal, with quotes doubled", () => {
  const result = queryUsersSecure("' OR '1'='1");
  assert.equal(result.sql, "SELECT * FROM users WHERE username = ''' OR ''1''=''1'");
});

test("SECURE: the bound payload is data, not syntax", () => {
  const result = queryUsersSecure("' OR '1'='1");
  // Even though the string contains " OR " and "=", the quote-aware parser
  // never sees them as operators, so the clause stays a single comparison.
  assert.equal(result.rowCount, 0);
});

test("SECURE: comment truncation inside a bound value is literal", () => {
  const result = queryUsersSecure("alice'--");
  assert.equal(result.rowCount, 0);
});

test("SECURE: normal lookups still work", () => {
  const result = queryUsersSecure("alice");
  assert.equal(result.rowCount, 1);
  assert.equal(result.rows[0]?.username, "alice");
});

test("SECURE and VULNERABLE agree on non-malicious input", () => {
  for (const username of ["alice", "bob", "carol", "nobody"]) {
    assert.equal(
      queryUsersVulnerable(username).rowCount,
      queryUsersSecure(username).rowCount,
      `lookup for "${username}" disagreed between the two implementations`,
    );
  }
});

test("no known payload changes the result under the secure query", () => {
  for (const payload of SQLI_PAYLOADS) {
    const result = queryUsersSecure(payload.value);
    assert.equal(
      isAuthenticationBypass(result, payload.value),
      false,
      `payload "${payload.name}" altered the secure query's meaning`,
    );
  }
});

test("every known payload IS a bypass under the vulnerable query", () => {
  for (const payload of SQLI_PAYLOADS) {
    const result = queryUsersVulnerable(payload.value);
    assert.ok(
      isAuthenticationBypass(result, payload.value),
      `payload "${payload.name}" did not bypass the vulnerable query`,
    );
  }
});

test("placeholderCount matches parameters for a well-formed statement", () => {
  const statement = prepare("SELECT * FROM users WHERE a = ? AND b = ?", 1, 2);
  assert.equal(placeholderCount(statement), 2);
  assert.equal(parametersMatch(statement), true);
  assert.equal(parameterCount(statement), 2);
});

test("parametersMatch catches a statement/parameter mismatch", () => {
  const broken = prepare("SELECT * FROM users WHERE a = ? AND b = ?", 1);
  assert.equal(parametersMatch(broken), false);
});

test("bind doubles quotes so a value cannot terminate its own literal", () => {
  const statement = prepare("SELECT * FROM t WHERE v = ?", "o'brien");
  assert.equal(bind(statement), "SELECT * FROM t WHERE v = 'o''brien'");
});

test("bind renders numbers and null without quoting", () => {
  assert.equal(bind(prepare("SELECT * FROM t WHERE a = ?", 42)), "SELECT * FROM t WHERE a = 42");
  assert.equal(bind(prepare("SELECT * FROM t WHERE a = ?", null)), "SELECT * FROM t WHERE a = NULL");
});