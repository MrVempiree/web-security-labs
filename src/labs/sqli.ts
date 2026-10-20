/**
 * Lab 2 — SQL Injection
 * OWASP Top 10: A03:2021 — Injection
 * CWE-89 — Improper Neutralization of Special Elements used in an SQL Command
 *
 * WHAT THIS LAB SHOWS
 * -------------------
 * SQL injection happens when user input is concatenated into SQL *text*.
 * Because the input becomes part of the statement's grammar, the attacker
 * stops supplying data and starts supplying syntax — adding an `OR` clause
 * that the database evaluates as true.
 *
 * The fix is not "sanitise the input". It is to stop concatenating. With a
 * parameterised query, the SQL text is fixed before the input is ever seen,
 * and the input can only ever be compared as a value.
 *
 * HONESTY NOTE ON THE ENGINE
 * --------------------------
 * This module implements a deliberately tiny evaluator rather than using a
 * real database. It supports exactly one statement shape:
 *
 *     SELECT * FROM <table> WHERE <comparison> [AND|OR <comparison>...]...
 *
 * where a comparison is `<operand> = <operand>` and an operand is either a
 * column name or a single-quoted literal. `--` and `#` comments are stripped.
 * The parser is quote-aware, which is the minimum needed for the demo to be
 * honest: a bound value containing `=` or the word `OR` must be treated as
 * data, not as syntax.
 *
 * It is NOT a SQL engine. It does not model dialect differences, type
 * coercion, collation, stacked queries, or blind/time-based techniques, and it
 * must not be mistaken for a general SQL parser.
 */

import { prepare, type PreparedStatement } from "../security.ts";
import { userRows } from "../store.ts";

export type SqlRow = Record<string, string | number | null>;

export type QueryResult = {
  readonly sql: string;
  readonly rows: readonly SqlRow[];
  readonly rowCount: number;
};

/* ------------------------------------------------------------------ *
 * A very small, quote-aware SQL evaluator
 * ------------------------------------------------------------------ */

type Operand =
  | { readonly kind: "column"; readonly name: string }
  | { readonly kind: "literal"; readonly value: string };

type Predicate =
  | { readonly kind: "compare"; readonly expression: Comparison }
  | { readonly kind: "and" | "or"; readonly left: Predicate; readonly right: Predicate };

type Comparison = {
  readonly left: Operand;
  readonly right: Operand;
};

/**
 * Strip an unquoted trailing comment (`--` or `#`) from a clause.
 *
 * Quote-aware: the `--` inside the literal `'alice'--'` must NOT be treated
 * as a comment, because the quote is still open at that point.
 */
export function stripComment(clause: string): string {
  let inQuote = false;
  for (let i = 0; i < clause.length; i += 1) {
    const char = clause[i];
    if (char === "'") {
      inQuote = !inQuote;
      continue;
    }
    if (inQuote) continue;
    const isLineComment = char === "-" && clause[i + 1] === "-";
    if (isLineComment || char === "#") {
      return clause.slice(0, i).trimEnd();
    }
  }
  return clause;
}

/**
 * Find a keyword (OR/AND) that sits outside any quoted literal.
 *
 * Returns the index and the length of the matched whitespace-delimited run,
 * so the caller can split without leaving stray spaces behind.
 */
function findKeyword(
  clause: string,
  keyword: "OR" | "AND",
): { index: number; length: number } | null {
  let inQuote = false;
  for (let i = 0; i < clause.length; i += 1) {
    const char = clause[i];
    if (char === "'") {
      inQuote = !inQuote;
      continue;
    }
    if (inQuote || char !== " ") continue;

    // Match whitespace + keyword + whitespace, case-insensitively.
    const rest = clause.slice(i);
    const match = new RegExp(`^\\s+${keyword}\\s+`, "i").exec(rest);
    if (match !== null) {
      return { index: i, length: match[0].length };
    }
  }
  return null;
}

/** Index of the `=` that sits outside any quoted literal, or -1. */
function findComparisonOperator(clause: string): number {
  let inQuote = false;
  for (let i = 0; i < clause.length; i += 1) {
    const char = clause[i];
    if (char === "'") {
      inQuote = !inQuote;
      continue;
    }
    if (!inQuote && char === "=") return i;
  }
  return -1;
}

function parseOperand(raw: string): Operand {
  const token = raw.trim();
  const quoted = /^'((?:[^']|'')*)'$/.exec(token);
  if (quoted !== null) {
    return { kind: "literal", value: (quoted[1] ?? "").replace(/''/g, "'") };
  }
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(token)) {
    return { kind: "column", name: token };
  }
  // Bare numeric literal, e.g. the `1=1` in the classic `' OR 1=1 --` payload.
  // Real SQL permits these unquoted, so refusing them would make the lab
  // reject a payload it is supposed to demonstrate.
  if (/^-?\d+(?:\.\d+)?$/.test(token)) {
    return { kind: "literal", value: token };
  }
  throw new Error(`Unsupported operand in WHERE clause: ${token}`);
}

function parseComparison(clause: string): Comparison {
  const equals = findComparisonOperator(clause);
  if (equals === -1) {
    throw new Error(`Expected a single '=' comparison, received: ${clause.trim()}`);
  }
  return {
    left: parseOperand(clause.slice(0, equals)),
    right: parseOperand(clause.slice(equals + 1)),
  };
}

/** OR binds looser than AND, matching standard SQL precedence. */
function parsePredicate(clause: string): Predicate {
  const or = findKeyword(clause, "OR");
  if (or !== null) {
    return {
      kind: "or",
      left: parsePredicate(clause.slice(0, or.index)),
      right: parsePredicate(clause.slice(or.index + or.length)),
    };
  }
  const and = findKeyword(clause, "AND");
  if (and !== null) {
    return {
      kind: "and",
      left: parsePredicate(clause.slice(0, and.index)),
      right: parsePredicate(clause.slice(and.index + and.length)),
    };
  }
  return { kind: "compare", expression: parseComparison(clause) };
}

function resolve(operand: Operand, row: SqlRow): string {
  if (operand.kind === "literal") return operand.value;
  const value = row[operand.name];
  return value === null || value === undefined ? "" : String(value);
}

function evaluate(predicate: Predicate, row: SqlRow): boolean {
  switch (predicate.kind) {
    case "compare":
      return (
        resolve(predicate.expression.left, row) ===
        resolve(predicate.expression.right, row)
      );
    case "and":
      return evaluate(predicate.left, row) && evaluate(predicate.right, row);
    case "or":
      return evaluate(predicate.left, row) || evaluate(predicate.right, row);
  }
}

/** Run the one supported statement shape against an in-memory row set. */
export function runQuery(sql: string, rows: readonly SqlRow[]): readonly SqlRow[] {
  const match = /^SELECT\s+\*\s+FROM\s+([A-Za-z_][A-Za-z0-9_]*)\s+WHERE\s+(.+)$/i.exec(
    sql.trim(),
  );
  if (match === null) {
    throw new Error(
      "Unsupported statement. This lab only evaluates " +
        `"SELECT * FROM <table> WHERE <comparison> [AND|OR <comparison>...]".`,
    );
  }
  const predicate = parsePredicate(stripComment(match[2] ?? ""));
  return rows.filter((row) => evaluate(predicate, row));
}

/**
 * Substitute `?` placeholders with quoted, escaped literals.
 *
 * This models what a real database driver's parameter binding does: the value
 * is transported separately and only ever becomes a literal, never syntax. A
 * payload containing a quote has it doubled, so it cannot terminate the
 * literal and start a new clause.
 */
export function bind(statement: PreparedStatement): string {
  let index = 0;
  return statement.sql.replace(/\?/g, () => {
    const value = statement.params[index];
    index += 1;
    if (value === null) return "NULL";
    if (typeof value === "number") return String(value);
    return `'${String(value).replace(/'/g, "''")}'`;
  });
}

/* ------------------------------------------------------------------ *
 * Vulnerable and secure query builders
 * ------------------------------------------------------------------ */

/**
 * VULNERABLE — string concatenation.
 *
 * The attacker's input is spliced into the statement text, so it can close the
 * literal, append an `OR` clause, and reopen a literal. The resulting WHERE
 * clause is true for every row.
 */
export function queryUsersVulnerable(username: string): QueryResult {
  const sql = `SELECT * FROM users WHERE username = '${username}'`;
  const rows = runQuery(sql, userRows());
  return { sql, rows, rowCount: rows.length };
}

/**
 * SECURE — parameterised query.
 *
 * The SQL text is constant. The attacker still controls the *value* they are
 * compared against, but they cannot add syntax, so the clause stays true only
 * for rows whose username literally equals the payload.
 */
export function queryUsersSecure(username: string): QueryResult {
  const statement = prepare(
    "SELECT * FROM users WHERE username = ?",
    username,
  );
  const sql = bind(statement);
  const rows = runQuery(sql, userRows());
  return { sql, rows, rowCount: rows.length };
}

/**
 * Known injection payloads, used by the tests and the demo route.
 *
 * Scope note: every payload here is one this lab's evaluator can actually
 * parse, so each produces a demonstrable result. UNION-based payloads are
 * deliberately NOT listed, because this toy engine supports a single statement
 * shape and rejects them — see the dedicated test for that limitation.
 */
export const SQLI_PAYLOADS: ReadonlyArray<{ readonly name: string; readonly value: string }> = [
  { name: "tautology", value: "' OR '1'='1" },
  { name: "numeric tautology", value: "' OR 1=1 --" },
  { name: "prefixed tautology", value: "x' OR '1'='1" },
  { name: "comment truncation", value: "alice'--" },
];

/**
 * Did the input change the meaning of the query?
 *
 * Defined rigorously rather than by a heuristic: run the same value through
 * the PARAMETERISED implementation, which is known-safe, and compare row
 * counts. If the concatenated version returns a different number of rows than
 * the safe version, the input altered the query's structure rather than merely
 * being compared as a value.
 *
 * This correctly flags a tautology (3 rows vs 0) and a comment-truncation
 * payload (1 row vs 0), and correctly ignores benign lookups (1 row vs 1).
 */
export function isAuthenticationBypass(
  result: QueryResult,
  username: string,
): boolean {
  return result.rowCount !== queryUsersSecure(username).rowCount;
}