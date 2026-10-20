/**
 * Lab 1 — Cross-Site Scripting (XSS)
 * OWASP Top 10: A03:2021 — Injection
 * CWE-79 — Improper Neutralization of Input During Web Page Generation
 *
 * WHAT THIS LAB SHOWS
 * -------------------
 * XSS happens when data that a user controls is placed into an HTML document
 * without being encoded for that document context. The browser cannot tell the
 * difference between markup the developer intended and markup an attacker
 * supplied, so attacker-supplied `<script>` runs with the victim's privileges.
 *
 * This module pairs a deliberately broken renderer with a correct one, so the
 * difference is a single readable diff rather than an abstract principle.
 *
 * SCOPE AND LIMITATIONS (read before drawing conclusions)
 * -------------------------------------------------------
 *  - The lab covers reflected XSS in HTML body and double-quoted attribute
 *    contexts, plus a contrast with the JavaScript-string context. It does NOT
 *    model DOM-based XSS, stored XSS, mutation XSS, or context-specific
 *    parsing quirks of specific browsers.
 *  - No browser is involved. These tests assert on the generated markup, not
 *    on observed script execution. That is a weaker claim than "this executes
 *    in Chrome", and it is deliberately the claim made.
 *  - `escapeHtml` is a mitigation, not a guarantee. Context matters: correct
 *    HTML encoding is not sufficient for a JavaScript string, a URL, a CSS
 *    value, or an unquoted attribute. The primary controls are a restrictive
 *    Content-Security-Policy and not emitting user data into executable
 *    contexts at all.
 */

import { escapeHtml, escapeJsString } from "../security.ts";

export type RenderResult = {
  readonly html: string;
  /**
   * True when the untrusted input appears VERBATIM in the output.
   *
   * This is the meaningful signal for a full document: a page legitimately
   * contains real tags, so "does the output contain angle brackets" says
   * nothing. "Did the attacker's bytes survive unencoded" does.
   */
  readonly inputEchoedRaw: boolean;
};

/** Build a result, measuring whether the raw input survived into the output. */
function render(input: string, html: string): RenderResult {
  return { html, inputEchoedRaw: echoesInputRaw(html, input) };
}

/**
 * VULNERABLE — reflected XSS via unencoded interpolation.
 *
 * The profile bio is concatenated straight into the response body. An attacker
 * controls `bio`, so an attacker controls the HTML.
 *
 * Do not copy this. It exists to be read next to `renderProfileSecure`.
 */
export function renderProfileVulnerable(username: string, bio: string): RenderResult {
  const html = `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Profile: ${username}</title></head>
  <body>
    <h1>${username}</h1>
    <p class="bio">${bio}</p>
  </body>
</html>`;
  return render(bio, html);
}

/**
 * SECURE — same output, with the bio encoded for an HTML context.
 *
 * The injected payload is now inert text. It renders on screen as the literal
 * characters the attacker typed, which is the correct outcome.
 */
export function renderProfileSecure(username: string, bio: string): RenderResult {
  const safeUsername = escapeHtml(username);
  const safeBio = escapeHtml(bio);
  const html = `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Profile: ${safeUsername}</title></head>
  <body>
    <h1>${safeUsername}</h1>
    <p class="bio">${safeBio}</p>
  </body>
</html>`;
  return render(bio, html);
}

/**
 * VULNERABLE — attribute-context injection.
 *
 * The bio is placed inside a double-quoted `title` attribute without
 * encoding. Body-context encoding alone would not save this: the attacker
 * breaks out of the attribute instead of the element.
 */
export function renderTooltipVulnerable(bio: string): RenderResult {
  const html = `<span class="badge" title="${bio}">hover me</span>`;
  return render(bio, html);
}

/**
 * SECURE — attribute-context injection, remediated.
 *
 * `escapeHtml` encodes the quote character, so the payload cannot terminate
 * the attribute.
 */
export function renderTooltipSecure(bio: string): RenderResult {
  const html = `<span class="badge" title="${escapeHtml(bio)}">hover me</span>`;
  return render(bio, html);
}

/**
 * SECURE, and the one I would actually ship — build the page without putting
 * user data into an executable context at all.
 *
 * The greeting is emitted as a `data-` attribute and read by script, so the
 * browser never parses it as markup or script. Encoding is still applied as
 * defence in depth, but the structure no longer depends on it.
 */
export function renderGreetingSecure(userInput: string): RenderResult {
  const html = `<!doctype html>
<html lang="en">
  <body>
    <span id="greeting" data-name="${escapeHtml(userInput)}"></span>
    <script>
      const el = document.getElementById("greeting");
      if (el) el.textContent = "Hello, " + el.dataset.name;
    </script>
  </body>
</html>`;
  return render(userInput, html);
}

/**
 * VULNERABLE — user data embedded in a JavaScript string literal.
 *
 * Note this is the classic case where *HTML* encoding is not the right fix:
 * escaping for HTML would not prevent breaking out of the JS string. The
 * correct primary fix is `renderGreetingSecure`, which avoids the context
 * entirely; `escapeJsString` is the narrower mitigation shown for contrast.
 */
export function renderScriptVulnerable(userInput: string): RenderResult {
  const html = `<script>const user = "${userInput}";</script>`;
  return render(userInput, html);
}

/** SECURE (narrow) — JavaScript-string escaping. */
export function renderScriptEscaped(userInput: string): RenderResult {
  const html = `<script>const user = "${escapeJsString(userInput)}";</script>`;
  return render(userInput, html);
}

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

/** Known XSS payloads, used by the tests and by the demo routes. */
export const XSS_PAYLOADS: ReadonlyArray<{ readonly name: string; readonly value: string }> = [
  { name: "script tag", value: "<script>alert('xss')</script>" },
  { name: "img onerror", value: "<img src=x onerror=alert('xss')>" },
  { name: "attribute breakout", value: '" onmouseover="alert(\'xss\')' },
  { name: "javascript: URL", value: "<a href='javascript:alert(1)'>click</a>" },
];

/**
 * True when the raw input appears verbatim in the generated output.
 *
 * This is the load-bearing security assertion for this lab: if the attacker's
 * exact bytes survive into the markup, they were not encoded.
 *
 * Limitation: benign input (plain text) is echoed verbatim by BOTH the
 * vulnerable and secure renderers, because it needs no encoding. So a `true`
 * here is only evidence of a problem when the input contains markup
 * characters — which is why callers test with payloads, not with "hello".
 */
export function echoesInputRaw(html: string, input: string): boolean {
  return input !== "" && html.includes(input);
}

/**
 * Detect angle brackets in an output FRAGMENT.
 *
 * Only meaningful for fragment-level renders such as `renderTooltip*`, where
 * there is no surrounding template. Do not apply it to a full document: every
 * document contains real tags, so the answer is always `true`.
 */
export function hasRawMarkup(html: string): boolean {
  return /[<>]/.test(html);
}

/**
 * True if the document still contains a script element.
 * Note this is a marker check on generated text, not proof of execution.
 */
export function containsScriptTag(html: string): boolean {
  return /<script\b/i.test(html);
}