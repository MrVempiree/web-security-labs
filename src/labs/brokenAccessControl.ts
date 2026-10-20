/**
 * Lab 3 — Broken Access Control / IDOR
 * OWASP Top 10: A01:2021 — Broken Access Control
 * CWE-639 — Authorization Bypass Through User-Controlled Key
 *
 * WHAT THIS LAB SHOWS
 * -------------------
 * Broken access control is the single most common high-severity web flaw.
 * The typical shape is an endpoint that checks *whether* a caller is logged
 * in, but never checks *whether the thing being requested belongs to them*.
 *
 * That missing check is an Insecure Direct Object Reference (IDOR). The
 * endpoint is not "unprotected" — it is protected by the wrong rule. Swap the
 * object ID and the response changes.
 *
 * SCOPE AND LIMITATIONS
 * ---------------------
 *  - Models a single-session, single-tenant authorisation check.
 *  - Does NOT model multi-tenant scoping, role-based access control,
 *    field-level authorisation, or rate limiting on enumeration.
 *  - In production, object-level checks must be applied at the data layer,
 *    not by remembering to add them to each handler. This lab's "secure" path
 *    shows the check; it does not prove your codebase will not forget it
 *    somewhere else.
 */

import { authorizeRead, type AuthzFailure } from "../security.ts";
import { findNoteById, type NoteRecord } from "../store.ts";

export type Session = { readonly userId: string };

export type AccessResult =
  | {
      readonly outcome: "allowed";
      readonly status: 200;
      readonly note: NoteRecord;
    }
  | {
      readonly outcome: "denied";
      readonly status: 401 | 403;
      readonly error: "unauthenticated" | "forbidden";
    };

/* ------------------------------------------------------------------ *
 * VULNERABLE
 * ------------------------------------------------------------------ */

/**
 * VULNERABLE — authenticates, but never authorises.
 *
 * The handler checks that *a* session exists and then returns whatever object
 * was asked for. Because `id` comes straight from the URL, any authenticated
 * user can read any note by changing one number.
 */
export function readNoteVulnerable(
  session: Session | null,
  id: number,
): AccessResult {
  if (session === null) {
    // Authentication is checked. Authorization is not. This is the bug.
    return { outcome: "denied", status: 401, error: "unauthenticated" };
  }
  const note = findNoteById(id);
  if (note === null) {
    return { outcome: "denied", status: 403, error: "forbidden" };
  }
  return { outcome: "allowed", status: 200, note };
}

/* ------------------------------------------------------------------ *
 * SECURE
 * ------------------------------------------------------------------ */

/**
 * SECURE — authenticates *and* authorises.
 *
 * The record is fetched, then ownership is verified against the session
 * before it is returned. Note that "not found" and "not yours" collapse to
 * the same 403: distinguishing them would confirm that a note ID exists, which
 * is itself a disclosure.
 */
export function readNoteSecure(
  session: Session | null,
  id: number,
): AccessResult {
  const note = findNoteById(id);
  const decision: AuthzFailure = authorizeRead(session, note);

  if (!decision.ok) {
    return {
      outcome: "denied",
      status: decision.status,
      error: decision.error,
    };
  }
  // `authorizeRead` proved the caller owns the record, but it returns the
  // generic record type, so the shape is restored for the caller.
  return { outcome: "allowed", status: 200, note: note as NoteRecord };
}

/* ------------------------------------------------------------------ *
 * Enumeration — the second-order problem
 * ------------------------------------------------------------------ */

/**
 * Demonstrate that object IDs are guessable.
 *
 * A secure handler stops cross-user reads, but sequential integer IDs still
 * let an attacker *try* every one of them. This helper exists to make that
 * residual risk explicit rather than to claim the secure path is total.
 *
 * In production the mitigations are: opaque random identifiers, rate limiting,
 * and monitoring on repeated authorisation failures.
 */
export function probeAllNotes(
  session: Session | null,
  maxId: number,
  read: (session: Session | null, id: number) => AccessResult,
): AccessResult[] {
  const results: AccessResult[] = [];
  for (let id = 1; id <= maxId; id += 1) {
    results.push(read(session, id));
  }
  return results;
}

/** Synthetic sessions for the demo and the tests. */
export const SESSIONS: Readonly<Record<string, Session>> = {
  alice: { userId: "user-alice" },
  bob: { userId: "user-bob" },
  carol: { userId: "user-carol" },
};