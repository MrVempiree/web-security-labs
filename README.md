# web-security-labs

Reproducible web application security labs. Each lab pairs a **working vulnerable
implementation** with a **remediated one**, plus automated tests that prove the two
behave differently.

> **These labs contain deliberately vulnerable code. They bind to localhost only and
> must never be deployed. See [Safety](#safety) and [SECURITY.md](SECURITY.md).**

[![tests](https://img.shields.io/badge/tests-65%20passing-brightgreen)](https://github.com/MrVempiree/web-security-labs)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![deps](https://img.shields.io/badge/dependencies-0-success)](package.json)
[![node](https://img.shields.io/badge/node-%3E%3D22.6-5FA04E)](https://nodejs.org)

---

## What this is

Most XSS/SQLi tutorials give you a payload and a `curl` command. This gives you both
sides of the fix, in one readable file, with a test that fails if you break either.

The design principle is **the vulnerable function and the secure function live in the
same file, a few lines apart**. You do not have to remember which blog post said what.

| Lab | Vulnerability | What you learn |
|-----|---------------|----------------|
| [`src/labs/xss.ts`](src/labs/xss.ts) | XSS — CWE-79 | Context-aware output encoding, and why "escape everything" is not a strategy |
| [`src/labs/sqli.ts`](src/labs/sqli.ts) | SQL injection — CWE-89 | Why parameterised queries work structurally, not by filtering |
| [`src/labs/brokenAccessControl.ts`](src/labs/brokenAccessControl.ts) | IDOR — CWE-639 | Authenticating is not authorising |

## Who this helps

- Developers who have heard "use prepared statements" but have never seen *why* the
  injection stops working.
- Security students who want to move past `alert(1)` and into remediation.
- Reviewers who want a compact, runnable reference for what the fixes look like.

## Requirements

**Node.js 22.6 or newer.** Nothing else.

There is no build step, no `node_modules`, and no install step — the project has zero
runtime dependencies and runs TypeScript directly via Node's built-in type stripping.
A security tool that asks you to trust a 200-package dependency tree before it will
start is a bad security tool.

## Installation

```bash
git clone https://github.com/MrVempiree/web-security-labs.git
cd web-security-labs
```

That is the entire setup. There is nothing to install.

## Quick start

Run the tests:

```bash
npm test
```

Expected output:

```
# tests 65
# pass 65
# fail 0
```

Start the lab server:

```bash
npm start
# [lab-server] listening on http://127.0.0.1:8080
```

Then open <http://127.0.0.1:8080> for a list of every lab.

---

## Lab 1 — Cross-Site Scripting

**Try it:**

```bash
# VULNERABLE — the payload reaches the page as live markup
curl "http://127.0.0.1:8080/xss/vulnerable?bio=<script>alert(1)</script>"

# SECURE — same payload, encoded into inert text
curl "http://127.0.0.1:8080/xss/secure?bio=<script>alert(1)</script>"
```

**Expected output.** The vulnerable response contains a literal
`<script>alert(1)</script>` in the body. The secure response contains
`&lt;script&gt;alert(1)&lt;/script&gt;`, which renders as visible text.

**Why it works.** `renderProfileVulnerable` concatenates user input into HTML. The
browser cannot distinguish attacker markup from developer markup, so it executes.
`renderProfileSecure` runs the same input through `escapeHtml` first.

**The part people get wrong.** HTML-encoding fixes the *body* context and the
*attribute* context, but it does **not** fix a JavaScript string context. The lab
shows all three:

- `renderProfileSecure` — body context, HTML encoding is correct.
- `renderTooltipSecure` — attribute context; note body encoding alone would not have
  helped here, because the attacker breaks out of the quote rather than the tag.
- `renderGreetingSecure` — the fix I would actually ship: **do not put user data in an
  executable context at all.** Emit it as a `data-` attribute and read it via
  `textContent`. Encoding is still applied as defence in depth, but the structure no
  longer depends on it.

## Lab 2 — SQL Injection

**Try it:**

```bash
# VULNERABLE — returns all 3 accounts
curl "http://127.0.0.1:8080/sqli/vulnerable?name=' OR '1'='1"

# SECURE — returns 0 accounts
curl "http://127.0.0.1:8080/sqli/secure?name=' OR '1'='1"
```

**Expected output.**

```
vulnerable:  "sql": "SELECT * FROM users WHERE username = '' OR '1'='1'",  "rowCount": 3
secure:      "sql": "SELECT * FROM users WHERE username = ''' OR ''1''=''1'", "rowCount": 0
```

**Why it works.** In the vulnerable version the payload becomes *syntax* — it closes
the string literal, appends an always-true `OR`, and reopens the literal. In the
secure version the SQL text is fixed before the input is seen, so the payload is only
ever compared as a *value* and matches nothing.

**An important caveat about this lab.** It does **not** use a real database. It
implements a deliberately tiny, quote-aware evaluator that supports exactly one
statement shape:

```sql
SELECT * FROM <table> WHERE <comparison> [AND|OR <comparison>]...
```

It models the *structural* difference truthfully, which is the point. It does **not**
model dialect differences, type coercion, collation, stacked queries, or blind
techniques. A `UNION`-based payload is rejected by the evaluator rather than evaluated
— that is a limitation of the demo engine, not a claim that `UNION` is not a real
injection technique. There is a test documenting this explicitly so it cannot be
misread.

## Lab 3 — Broken Access Control (IDOR)

**Try it** (as `alice`, requesting a note owned by `bob`):

```bash
# VULNERABLE — 200 OK, returns bob's private note
curl "http://127.0.0.1:8080/idor/vulnerable?id=102&as=alice"

# SECURE — 403 Forbidden
curl -i "http://127.0.0.1:8080/idor/secure?id=102&as=alice"

# SECURE — alice reading her own note still works
curl "http://127.0.0.1:8080/idor/secure?id=101&as=alice"
```

**Expected output.**

| Request | Vulnerable | Secure |
|---|---|---|
| `alice` → bob's note (`id=102`) | `200 allowed`, owner `user-bob` | `403 forbidden` |
| `alice` → her own note (`id=101`) | `200 allowed` | `200 allowed` |
| no session | `401` | `401` |

**Why it works.** The vulnerable handler checks *whether a session exists* but never
checks *whether the object belongs to that session*. It is not unprotected — it is
protected by the wrong rule. Change one number in the URL and the response changes.

The secure path fetches the record, then verifies ownership before returning it. It
also returns `403` rather than `404` for someone else's record, and collapses
"not found" into "not yours" — distinguishing them would confirm that the ID exists,
which is itself a disclosure.

**The residual risk this lab does not solve.** Sequential integer IDs mean an attacker
can still *try* every one of them. `probeAllNotes` exists to make that visible: run it
and you can see the vulnerable path leaking all 3 records to one user. The mitigations
in production are opaque random identifiers, rate limiting, and alerting on repeated
authorisation failures.

---

## Architecture

```
web-security-labs/
├── src/
│   ├── config.ts                 Safety policy: loopback enforcement, port validation
│   ├── security.ts               The SECURE primitives (escaping, binding, authorization)
│   ├── store.ts                  Synthetic in-memory fixtures — no real data
│   ├── router.ts                 Minimal node:http routing
│   ├── server.ts                 Entry point; refuses unsafe binds
│   └── labs/
│       ├── xss.ts                Lab 1 — vulnerable + secure renderers
│       ├── sqli.ts               Lab 2 — query builders + tiny evaluator
│       └── brokenAccessControl.ts  Lab 3 — readNoteVulnerable / readNoteSecure
├── tests/
│   ├── xss.test.ts
│   ├── sqli.test.ts
│   ├── brokenAccessControl.test.ts
│   └── safety.test.ts            The most important tests in the repo
└── .github/workflows/ci.yml
```

Every lab module exports both `...Vulnerable` and `...Secure` variants side by side,
and both are exercised by the tests.

## Testing

```bash
npm test
```

**What the tests actually assert.** They assert on *generated output* — the markup
that was produced, the rows that came back, the status that was returned. They do
**not** launch a browser or a real database. That is a narrower claim than "this
executes in Chrome", and it is deliberately the claim made here.

`safety.test.ts` is the most important file in the project. It asserts the property
that makes shipping vulnerable code acceptable at all: the server will not bind to a
routable interface without an explicit acknowledgement.

## Safety

The security controls, in order of importance:

1. **Default bind is `127.0.0.1`, never `0.0.0.0`.**
2. **A non-loopback bind is refused** unless you set `ALLOW_NON_LOOPBACK_BIND=1`.
   Anything other than exactly `1` is rejected.
3. **Startup exits non-zero on refusal** — a refusal cannot be scrolled past.
4. **All data is synthetic.** No real accounts, credentials, or addresses.

```bash
# Works
PORT=8080 npm start

# Refuses, and exits
HOST=0.0.0.0 npm start
# [lab-server] STARTUP REFUSED
# Refusing to bind to non-loopback address "0.0.0.0".
```

**What loopback binding does NOT protect against.** It reduces exposure; it does not
make the labs safe. Do not run them on a shared machine, on a VPS, in a container with
a published port, or behind a reverse proxy that forwards to them. Do not point the
`/sqli/vulnerable` or `/idor/vulnerable` routes at any system you do not own.

## Known limitations

Stated plainly, because a security tool that oversells itself is worse than no tool:

- **No real database.** The SQL lab uses a toy evaluator, not SQLite/Postgres. See the
  caveat above.
- **No browser.** XSS is asserted on markup, not on observed execution. No DOM-based
  or stored XSS is modelled.
- **Three labs only.** No CSRF, SSRF, file upload, path traversal, or session
  management yet.
- **No rate limiting or auth.** The `?as=` session parameter is a lab convenience, not
  a login system.
- **IDOR is single-tenant.** No multi-tenancy or RBAC modelling.
- **Not production-ready in any sense.** It is a teaching tool.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New labs are welcome — read the
[limitations](#known-limitations) section first so you know what "done" means here.

## License

[MIT](LICENSE)