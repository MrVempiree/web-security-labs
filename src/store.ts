/**
 * In-memory test data store.
 *
 * Deliberately not a real database: the SQL injection lab needs to demonstrate
 * how user input changes the *structure* of a query, not how a particular
 * database engine parses one. Keeping the store in-process means the project
 * has zero dependencies and runs anywhere Node runs.
 *
 * All records are synthetic. No real accounts, addresses, or credentials.
 */

export type UserRecord = {
  id: number;
  username: string;
  email: string;
  ownerId: string;
  bio: string;
};

export type NoteRecord = {
  id: number;
  ownerId: string;
  title: string;
  body: string;
};

/** Synthetic users. `ownerId` ties a record to the session that may read it. */
export const USERS: readonly UserRecord[] = [
  {
    id: 1,
    username: "alice",
    email: "alice@example.invalid",
    ownerId: "user-alice",
    bio: "Backend engineer. Coffee-driven.",
  },
  {
    id: 2,
    username: "bob",
    email: "bob@example.invalid",
    ownerId: "user-bob",
    bio: "Frontend developer. Ships fast.",
  },
  {
    id: 3,
    username: "carol",
    email: "carol@example.invalid",
    ownerId: "user-carol",
    bio: "Security analyst. Reads changelogs.",
  },
];

/** Synthetic private notes, used by the broken access control lab. */
export const NOTES: readonly NoteRecord[] = [
  {
    id: 101,
    ownerId: "user-alice",
    title: "Alice: sprint planning",
    body: "Ship the auth fix before Friday.",
  },
  {
    id: 102,
    ownerId: "user-bob",
    title: "Bob: deployment notes",
    body: "Rotate the staging credentials.",
  },
  {
    id: 103,
    ownerId: "user-carol",
    title: "Carol: audit checklist",
    body: "Check IDOR on every object endpoint.",
  },
];

/** Return a defensive copy so callers cannot mutate the fixture data. */
export function findUserById(id: number): UserRecord | null {
  const found = USERS.find((user) => user.id === id);
  return found === undefined ? null : { ...found };
}

export function findNoteById(id: number): NoteRecord | null {
  const found = NOTES.find((note) => note.id === id);
  return found === undefined ? null : { ...found };
}

export function findUserByUsername(username: string): UserRecord | null {
  const found = USERS.find((user) => user.username === username);
  return found === undefined ? null : { ...found };
}

/** All users as rows shaped for the toy SQL evaluator. */
export function userRows(): ReadonlyArray<Record<string, string | number | null>> {
  return USERS.map((user) => ({ ...user }));
}