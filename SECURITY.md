# Security Policy

## Scope of this project

`web-security-labs` is a **teaching tool**. It intentionally contains vulnerable code:
unencoded HTML output, concatenated SQL, and an endpoint that skips object-level
authorization.

The controls that make this acceptable are described below. They are tested in
[`tests/safety.test.ts`](tests/safety.test.ts) — if those tests fail, the project is
not safe to run.

## Reporting a vulnerability

**Report security issues in this repository privately.** Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Security" → "Report a vulnerability") on the repository page.

Please **do not** open a public issue for a vulnerability report.

### What counts as a report

Genuinely worth reporting:

- The server binding to a non-loopback interface **without** `ALLOW_NON_LOOPBACK_BIND=1`.
- A code path that bypasses the safety checks in `src/config.ts`.
- A genuine vulnerability in the *secure* implementations — for example, a bypass in
  `escapeHtml`, `bind`, or `authorizeRead`.
- A way to make the server read or write files outside its intended scope.

### What is NOT a vulnerability

These are the point of the project and will not be accepted as reports:

- The `/xss/vulnerable`, `/sqli/vulnerable` and `/idor/vulnerable` routes behaving
  vulnerably.
- Successful XSS, SQL injection, or IDOR against the lab server when it is running on
  localhost.
- The absence of authentication on the `?as=` session parameter.
- The toy SQL evaluator rejecting syntax it does not support. This is a documented
  limitation, not a flaw.

## Supported versions

Only the latest `main` branch is supported. There are no releases yet.

## Disclosure expectations

I aim to acknowledge a report within 72 hours and to fix confirmed issues before
publishing any public write-up. I am a solo maintainer, so please be patient.

## Responsible use

- Only run these labs on systems you own or have explicit written permission to assess.
- Do not point the vulnerable routes at third-party systems, even where you believe
  you have permission — verify that permission is in writing first.
- Do not use this project to attack infrastructure you do not control.
- If you find a vulnerability in a third-party system, follow that program's scope and
  disclosure rules, and report it privately to them.

## Security-relevant design decisions

1. **Loopback-only by default.** `DEFAULT_HOST` is `127.0.0.1`. It is never `0.0.0.0`.
2. **Explicit override required.** Non-loopback binds need `ALLOW_NON_LOOPBACK_BIND=1`
   exactly. `"true"`, `"yes"` and `""` are rejected.
3. **Fail closed.** A refused bind sets a non-zero exit code rather than starting in a
   degraded state.
4. **Zero dependencies.** No supply-chain surface to audit for a tool whose whole point
   is security.
5. **Synthetic data only.** No real accounts, credentials, or addresses.
6. **Errors do not leak.** The router returns a generic `internal error`; stack traces go
   to the server log, not the client.