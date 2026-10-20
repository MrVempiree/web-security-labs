/**
 * Secure implementation primitives.
 *
 * Every function here is the *remediated* counterpart to a vulnerable
 * function elsewhere in this project. Keeping them in one module makes the
 * correct approach easy to find, reuse, and test in isolation.
 *
 * The vulnerable versions deliberately live next to them in `labs/` so the
 * difference between "unsafe" and "safe" can be read side by side.
 */

/* ------------------------------------------------------------------ *
 * Output encoding (defence against Cross-Site Scripting)
 * ------------------------------------------------------------------ */

const HTML_ESCAPES: Readonly<Record<string, string>> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/**
 * Escape text for safe interpolation into HTML element content or a
 * double-quoted attribute value.
 *
 * This is the primary XSS defence. The order matters: the ampersand must be
 * escaped first, otherwise the ampersands introduced by later replacements
 * would be escaped a second time and produce corrupted output.
 */
export function escapeHtml(input: string): string {
  return input.replace(/[&<>"']/g, (char) => HTML_ESCAPES[char] ?? char);
}

/**
 * Escape text for use inside a JavaScript string literal that is embedded in
 * a <script> block.
 *
 * NOTE ON LIMITATIONS: this is a narrow, context-specific escaper. It is NOT a
 * complete defence, and it does not replace Content-Security-Policy. The
 * correct primary control is to not emit user data into a <script> context at
 * all — see `renderGreetingSecure` in `labs/xss.ts`, which does that instead.
 * This function exists to contrast with the raw-interpolation anti-pattern.
 */
export function escapeJsString(input: string): string {
  return input
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/</g, "\\u003C")
    .replace(/>/g, "\\u003E")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

/* ------------------------------------------------------------------ *
 * Parameterized queries (defence against SQL Injection)
 * ------------------------------------------------------------------ */

export type SqlValue = string | number | null;
export type SqlRow = Record<string, SqlValue>;

/**
 * A prepared statement: SQL text containing `?` placeholders, plus the
 * separately-supplied, separately-transported parameter list.
 *
 * The security property that matters: user input never becomes part of the
 * SQL *text*. It is only ever compared as a *value*. That is what makes the
 * query's structure unchangeable by the input.
 */
export type PreparedStatement = {
  readonly sql: string;
  readonly params: readonly SqlValue[];
};

export function prepare(sql: string, ...params: SqlValue[]): PreparedStatement {
  return { sql, params };
}

/**
 * Count how many `?` placeholders a statement declares.
 *
 * If this does not equal the number of bound parameters, the statement and
 * its parameters have drifted apart and the query is unsafe to run. This is
 * the check a hand-rolled string-building query never performs.
 */
export function placeholderCount(statement: PreparedStatement): number {
  return (statement.sql.match(/\?/g) ?? []).length;
}

/** Number of values bound to a statement. */
export function parameterCount(statement: PreparedStatement): number {
  return statement.params.length;
}

export function parametersMatch(statement: PreparedStatement): boolean {
  return placeholderCount(statement) === statement.params.length;
}

/* ------------------------------------------------------------------ *
 * Authorization (defence against Broken Access Control / IDOR)
 * ------------------------------------------------------------------ */

export type AuthzFailure =
  | { readonly ok: false; readonly status: 401; readonly error: "unauthenticated" }
  | { readonly ok: false; readonly status: 403; readonly error: "forbidden" }
  | { readonly ok: true; readonly record: Record<string, unknown> };

/**
 * Enforce object-level authorization: a caller may only read a record they
 * own.
 *
 * Two distinct failure modes are returned deliberately:
 *
 *  - 401 UNAUTHENTICATED — no valid session at all.
 *  - 403 FORBIDDEN — a valid session, but it does not own the requested object.
 *
 * Collapsing these into one error leaks the existence of the resource, which
 * is itself an information-disclosure flaw.
 */
export function authorizeRead(
  session: { userId: string } | null,
  record: Record<string, unknown> | null,
  ownerField = "ownerId",
): AuthzFailure {
  if (session === null) {
    return { ok: false, status: 401, error: "unauthenticated" };
  }
  if (record === null) {
    // Do not distinguish "does not exist" from "not yours" in the status.
    return { ok: false, status: 403, error: "forbidden" };
  }
  if (record[ownerField] !== session.userId) {
    return { ok: false, status: 403, error: "forbidden" };
  }
  return { ok: true, record };
}
