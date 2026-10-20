# Contributing

Thanks for considering a contribution.

## The bar for a lab

This project is a teaching tool, so a new lab is only useful if it teaches something
and is *honest* about what it does not cover. When you open a pull request for a new
lab, please include:

1. **A vulnerable and a secure implementation in the same module**, a few lines apart.
   This is the core design idea — please don't split them across files.
2. **Tests for both**, where the vulnerable tests assert the flaw is present and the
   secure tests assert it is absent.
3. **A `SCOPE AND LIMITATIONS` comment** at the top of the module stating what the lab
   does *not* model. This is required, not optional.
4. **OWASP and CWE references** in the module header.
5. **A README section** in the same style as the existing labs: what it is, how to try
   it, expected output, and why the fix works.

## Things that will get a PR rejected

- A lab with no vulnerable/secure pairing.
- A "fix" that only filters or blocklists input rather than fixing the structural
  cause. Input filtering is worth discussing, but it is not the lesson here.
- Claims in the README that the tests do not actually verify. If a test asserts on
  generated markup, do not write "this executes in a browser."
- A new runtime dependency. The zero-dependency property is deliberate and I will
  fight to keep it.
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

Node.js 22.6+ is required because the project relies on Node's built-in TypeScript
type stripping. There is no build step.

## Style

- Match the surrounding code. Comments explain *why*, not *what*.
- Use British-ish spelling in prose ("behaviour", "defence") to match the existing
  files. Do not reformat code you are not otherwise changing.
- Keep modules focused. A lab module should be readable in one sitting.

## Adding an endpoint

If you add a route in `src/router.ts`, also add it to the index page at `"/"` so the
lab is discoverable, and make sure any new query parameter is validated rather than
passed through unchecked.