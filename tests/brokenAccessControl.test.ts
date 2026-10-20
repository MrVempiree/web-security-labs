/**
 * Lab 3 tests — Broken Access Control / IDOR.
 *
 * The cross-user read is the headline assertion: the same request must
 * succeed against the vulnerable handler and fail against the secure one.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  probeAllNotes,
  readNoteSecure,
  readNoteVulnerable,
  SESSIONS,
} from "../src/labs/brokenAccessControl.ts";
import { authorizeRead } from "../src/security.ts";
import { NOTES } from "../src/store.ts";

const alice = SESSIONS["alice"]!;
const bob = SESSIONS["bob"]!;

const ALICE_NOTE_ID = 101;
const BOB_NOTE_ID = 102;
const CAROL_NOTE_ID = 103;

test("VULNERABLE: alice can read bob's note by changing the id", () => {
  const result = readNoteVulnerable(alice, BOB_NOTE_ID);

  assert.equal(result.outcome, "allowed");
  assert.equal(result.status, 200);
  assert.equal(result.status === 200 ? result.note.ownerId : null, "user-bob");
});

test("VULNERABLE: any authenticated user can read any note", () => {
  for (const session of [alice, bob, SESSIONS["carol"]!]) {
    const result = readNoteVulnerable(session, CAROL_NOTE_ID);
    assert.equal(result.outcome, "allowed");
  }
});

test("VULNERABLE: unauthenticated access is still rejected", () => {
  // The bug is a missing authorisation check, not a missing login check.
  // Being explicit here stops the lab from being misread as "no auth at all".
  const result = readNoteVulnerable(null, ALICE_NOTE_ID);
  assert.equal(result.outcome, "denied");
  assert.equal(result.status, 401);
});

test("SECURE: alice cannot read bob's note", () => {
  const result = readNoteSecure(alice, BOB_NOTE_ID);

  assert.equal(result.outcome, "denied");
  assert.equal(result.status, 403);
  assert.equal(result.error, "forbidden");
});

test("SECURE: each user can still read their own note", () => {
  const cases: ReadonlyArray<[typeof alice, number, string]> = [
    [alice, ALICE_NOTE_ID, "user-alice"],
    [bob, BOB_NOTE_ID, "user-bob"],
    [SESSIONS["carol"]!, CAROL_NOTE_ID, "user-carol"],
  ];
  for (const [session, id, ownerId] of cases) {
    const result = readNoteSecure(session, id);
    assert.equal(result.outcome, "allowed");
    assert.equal(result.status === 200 ? result.note.ownerId : null, ownerId);
  }
});

test("SECURE: no session yields 401, not 403", () => {
  const result = readNoteSecure(null, ALICE_NOTE_ID);
  assert.equal(result.status, 401);
  assert.equal(result.error, "unauthenticated");
});

test("SECURE: a missing note is indistinguishable from a forbidden one", () => {
  const missing = readNoteSecure(alice, 999);
  const forbidden = readNoteSecure(alice, BOB_NOTE_ID);

  assert.equal(missing.status, forbidden.status);
  assert.equal(missing.error, forbidden.error);
});

test("SECURE: enumeration via probeAllNotes yields only owned records", () => {
  const results = probeAllNotes(alice, 200, readNoteSecure);
  const allowed = results.filter((r) => r.outcome === "allowed");

  assert.equal(allowed.length, 1);
  assert.equal(allowed[0]?.status === 200 ? allowed[0].note.id : null, ALICE_NOTE_ID);
});

test("VULNERABLE: enumeration exposes every record", () => {
  const results = probeAllNotes(alice, 200, readNoteVulnerable);
  const allowed = results.filter((r) => r.outcome === "allowed");

  // Documents the scale of the disclosure: three synthetic notes, all leaked.
  assert.equal(allowed.length, NOTES.length);
});

test("authorizeRead requires an exact owner match", () => {
  const note = { ownerId: "user-alice" };

  assert.equal(authorizeRead(alice, note).ok, true);
  assert.equal(authorizeRead(bob, note).ok, false);
});

test("authorizeRead honours a custom owner field", () => {
  const project = { creatorId: "user-bob" };
  const decision = authorizeRead(bob, project, "creatorId");
  assert.equal(decision.ok, true);
});

test("authorizeRead treats a null record as forbidden, not missing", () => {
  const decision = authorizeRead(alice, null);
  assert.equal(decision.ok, false);
  assert.equal(decision.ok === false ? decision.status : 0, 403);
});