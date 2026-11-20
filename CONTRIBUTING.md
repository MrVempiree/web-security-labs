# Contributing

Thanks for considering a contribution.

## Lab safety and authorized use — read this first

This project ships intentionally vulnerable code so people can learn how attacks work and how to fix them. That makes the safety rules non-negotiable:

- **Only run these labs against your own lab targets.** Run the lab server on your own machine, in your own isolated environment, against the lab's own synthetic data. Never point these techniques at a website, app, or system you do not own.
- **Never test on systems without written authorization.** Practicing on a real site, a friend's site, or a production system without explicit, written permission is unauthorized access — even if you mean well. If you do not own it and do not have written permission, do not touch it.
- **Keep the labs local.** The lab server binds to loopback (`127.0.0.1`) on purpose and refuses to bind a public interface unless `ALLOW_NON_LOOPBACK_BIND=1` is set. Do not override that, do not expose the lab server to a network, and do not deploy a vulnerable lab anywhere other people can reach it.
- **Synthetic data only.** Labs use fake users, fake posts, and fake secrets. Never load real credentials, real user data, or production data into a lab.
- **Report real vulnerabilities responsibly.** If you find a flaw in a real product while learning here, report it through that product's own security contact or bug-bounty channel — do not exploit it, and do not publish it first.

Contributions that weaken these protections, or that encourage running labs against other people's systems, will be rejected.

## Setting up and running the labs locally (isolated environment)

You need Node.js 22.6 or later. There are no runtime dependencies and nothing to install:

1. Clone the repo and enter it:

   ```sh
   git clone https://github.com/MrVempiree/web-security-labs.git
   cd web-security-labs
   ```

2. Run the tests (65 of them, using Node's built-in runner):

   ```sh
   npm test
   ```

3. Start the lab server:

   ```sh
   npm start
   ```

   It serves on `http://127.0.0.1:8080` — loopback only.

Keep the run isolated:

- Run the labs on your own machine, a local VM, or a container that is not reachable from other machines. Do not put the server on a shared host or a public network.
- Do not change the loopback binding, and do not set `ALLOW_NON_LOOPBACK_BIND=1`, unless you fully understand the risk and are on an isolated network you control.
- Keep each experiment inside the lab: use the lab's own fake accounts (for example `alice` / `password123` in the broken-access-control lab) and its synthetic data.
- When you are done, stop the server (`Ctrl+C`). Nothing is installed on your system and no data leaves your machine.

## The bar for a lab

This project is a teaching tool, so a new lab is only useful if it teaches something and is *honest* about what it does not cover. When you open a pull request for a new lab, please include:

1. **A vulnerable and a secure implementation in the same module**, a few lines apart. This is the core design idea — please don't split them across files.
2. **Tests for both**, where the vulnerable tests assert the flaw is present and the secure tests assert it is absent. Use `tests/safety.test.ts` as a model.
3. **A `SCOPE AND LIMITATIONS` comment** at the top of the module stating what the lab does *not* model. This is required, not optional.
4. **OWASP and CWE references** in the module header.
5. **A README section** in the same style as the existing labs: what it is, how to try it, expected output, and why the fix works.

## Proposing a new lab

Before writing code, say what you plan to build — open an issue, or describe the idea at the top of your pull request: which vulnerability it teaches (with its CWE number), what the vulnerable behavior is, and what the secure fix demonstrates.

### Structure

One lab = one module plus its tests plus its docs:

- `src/labs/<lab>.ts` — one module per lab, exporting both the vulnerable and the secure implementation from the same module (see [The bar for a lab](#the-bar-for-a-lab)). Keep the two implementations a few lines apart so a learner can compare them directly. Add the `SCOPE AND LIMITATIONS` comment and the OWASP and CWE references in the module header.
- `tests/<lab>.test.ts` — tests for both implementations: the vulnerable tests assert the flaw is present, the secure tests assert it is absent. `tests/safety.test.ts` is the model, and the most important suite in the repo.
- A route in `src/router.ts` so the lab is reachable from the lab server (see [Adding an endpoint](#adding-an-endpoint)), plus a link on the index page at `"/"` so the lab is discoverable.

### README per lab

Every lab gets its own README section in `README.md`, in the same style as the existing labs:

- What the lab is, and which CWE it covers.
- How to try it, with a minimal payload, and the expected output.
- Why the fix works.
- "What this lab does not show" — an explicit list of limitations. If a lab needs more room than a section allows, add a `README.md` next to the module instead, and link it from the main README.
- Never claim the lab covers more than the tests verify. If a test asserts on generated markup, do not write "this executes in a browser."

### Difficulty label

Give the lab a difficulty label so learners can pick labs at their level. Put it in the pull request description (for example `difficulty: easy`, `difficulty: medium`, or `difficulty: hard`):

- **Easy** — a single flaw with a straightforward payload.
- **Medium** — chained steps, or a flaw that needs a bypass of a partial fix.
- **Hard** — a subtle flaw that needs a non-obvious payload, or a bypass of a fix that looks correct.

## Things that will get a PR rejected

- A lab with no vulnerable/secure pairing.
- A "fix" that only filters or blocklists input rather than fixing the structural cause. Input filtering is worth discussing, but it is not the lesson here.
- Claims in the README that the tests do not actually verify. If a test asserts on generated markup, do not write "this executes in a browser."
- A new runtime dependency. The zero-dependency property is deliberate and I will fight to keep it.
- Anything that weakens the loopback binding policy in `src/config.ts`.

## Development

```bash
# Run the tests (no install step required)
npm test

# Start the lab server
npm start

# Optional: typecheck, if you have TypeScript available
npm run typecheck
```

Node.js 22.6+ is required because the project relies on Node's built-in TypeScript type stripping. There is no build step.

## Style

- Match the surrounding code. Comments explain *why*, not *what*.
- Use British-ish spelling in prose ("behaviour", "defence") to match the existing files. Do not reformat code you are not otherwise changing.
- Keep modules focused. A lab module should be readable in one sitting.

## Adding an endpoint

If you add a route in `src/router.ts`, also add it to the index page at `"/"` so the lab is discoverable, and make sure any new query parameter is validated rather than passed through unchecked.

## Pull request expectations

- **One lab (or one fix) per pull request.** Keep the diff focused; a PR that mixes a new lab with unrelated changes is hard to review.
- **Branch from `main`** and keep the branch up to date.
- **Describe the change in the pull request:** what the lab or fix is, the CWE it covers, its difficulty label (`difficulty: easy | medium | hard`), how you tested it, and the limits of what it does not cover.
- **Tests and typecheck must pass before you open the PR:** run `npm test` and `npm run typecheck`. `tests/safety.test.ts` is the most important suite — never weaken it to make a PR pass.
- **Keep the zero-dependency rule.** Do not add runtime dependencies.
- **Do not reformat unrelated code,** and do not touch `src/config.ts` unless the PR is about the safety policy itself (and say so in the PR description).
- **Expect review.** The maintainer reviews and merges; be ready to answer review comments and adjust the lab, its tests, or its README section.
