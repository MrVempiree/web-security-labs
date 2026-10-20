/**
 * Lab 1 tests — Cross-Site Scripting.
 *
 * Each test asserts on the *generated markup*, not on browser execution. That
 * is a deliberately narrower claim: these tests prove encoding happened, they
 * do not prove a payload fired in a real browser.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  containsScriptTag,
  echoesInputRaw,
  hasRawMarkup,
  renderGreetingSecure,
  renderProfileSecure,
  renderProfileVulnerable,
  renderScriptEscaped,
  renderScriptVulnerable,
  renderTooltipSecure,
  renderTooltipVulnerable,
  XSS_PAYLOADS,
} from "../src/labs/xss.ts";
import { escapeHtml } from "../src/security.ts";

test("escapeHtml encodes every dangerous character", () => {
  assert.equal(escapeHtml("<"), "&lt;");
  assert.equal(escapeHtml(">"), "&gt;");
  assert.equal(escapeHtml('"'), "&quot;");
  assert.equal(escapeHtml("'"), "&#39;");
  assert.equal(escapeHtml("&"), "&amp;");
});

test("escapeHtml escapes ampersand first, without double-encoding", () => {
  // "&lt;" must become "&amp;lt;" — not "&amp;amp;lt;".
  assert.equal(escapeHtml("&lt;"), "&amp;lt;");
  assert.equal(escapeHtml("a & b"), "a &amp; b");
});

test("VULNERABLE: a script payload survives into the markup", () => {
  const payload = "<script>alert('xss')</script>";
  const result = renderProfileVulnerable("demo", payload);

  assert.ok(result.html.includes(payload));
  assert.equal(result.inputEchoedRaw, true);
  assert.ok(containsScriptTag(result.html));
});

test("SECURE: the same payload is neutralised in the body context", () => {
  const payload = "<script>alert('xss')</script>";
  const result = renderProfileSecure("demo", payload);

  assert.equal(result.html.includes(payload), false);
  assert.equal(result.inputEchoedRaw, false);
  assert.ok(result.html.includes("&lt;script&gt;"));
  assert.equal(
    containsScriptTag(result.html),
    false,
    "no executable script element should remain from user input",
  );
});

test("SECURE: the username is encoded too, not just the bio", () => {
  const result = renderProfileSecure("<admin>", "hello");
  assert.ok(result.html.includes("&lt;admin&gt;"));
  assert.equal(result.html.includes("<admin>"), false);
});

test("VULNERABLE: attribute context allows breakout", () => {
  const payload = '" onmouseover="alert(1)';
  const result = renderTooltipVulnerable(payload);

  // The quote closes the attribute and the handler becomes a real attribute.
  assert.equal(result.html.includes(payload), true);
  assert.ok(result.html.includes('title="" onmouseover="alert(1)"'));
  assert.equal(result.inputEchoedRaw, true);
});

test("SECURE: attribute breakout is prevented by encoding the quote", () => {
  const payload = '" onmouseover="alert(1)';
  const result = renderTooltipSecure(payload);

  assert.ok(result.html.includes("&quot;"));
  assert.equal(result.html.includes(payload), false);
  assert.equal(result.html.includes('onmouseover="alert'), false);
  assert.equal(result.inputEchoedRaw, false);
});

test("SECURE: the greeting lab never places user data in a script context", () => {
  const payload = "</script><script>alert(1)</script>";
  const result = renderGreetingSecure(payload);

  // The only <script> in the output is the lab's own, and it reads from a
  // data attribute rather than an interpolated literal.
  const scriptMatches = result.html.match(/<script\b/gi) ?? [];
  assert.equal(scriptMatches.length, 1);
  assert.ok(result.html.includes("el.dataset.name"));
  assert.equal(result.html.includes(payload), false);
  assert.equal(result.inputEchoedRaw, false);
});

test("VULNERABLE: raw interpolation into a script literal is injectable", () => {
  const payload = '"; alert(1); //';
  const result = renderScriptVulnerable(payload);

  // The payload terminates the string literal, so the call escapes it.
  assert.ok(result.html.includes(`const user = "${payload}"`));
  assert.equal(result.inputEchoedRaw, true);
});

test("SECURE: script-literal escaping escapes the quote terminator", () => {
  const payload = '"; alert(1); //';
  const result = renderScriptEscaped(payload);

  // The dangerous raw form is gone, and the quote now carries a backslash.
  assert.equal(result.html.includes(`const user = "${payload}"`), false);
  assert.ok(result.html.includes('\\"'));

  // NOTE: `inputEchoedRaw` is deliberately NOT asserted here. In a script
  // context the payload bytes still appear — they are just escaped, which is
  // what makes them inert. Byte-level echo is the wrong signal for this
  // context; the absence of the raw terminator is the right one.
});

test("SECURE: the script escaper also encodes angle brackets", () => {
  const payload = "<script>";
  const result = renderScriptEscaped(payload);

  assert.ok(result.html.includes("\\u003C"));
  assert.ok(result.html.includes("\\u003E"));

  // Assert on the literal, not on "<script>" generally: the output legitimately
  // begins with the lab's own <script> element.
  assert.equal(result.html.includes(`const user = "${payload}"`), false);
});

test("every known payload is neutralised by the secure body renderer", () => {
  for (const payload of XSS_PAYLOADS) {
    const result = renderProfileSecure("demo", payload.value);
    assert.equal(
      result.inputEchoedRaw,
      false,
      `payload "${payload.name}" was echoed raw by the secure renderer`,
    );
  }
});

test("every known payload IS echoed raw by the vulnerable renderer", () => {
  for (const payload of XSS_PAYLOADS) {
    const result = renderProfileVulnerable("demo", payload.value);
    assert.equal(
      result.inputEchoedRaw,
      true,
      `payload "${payload.name}" did not reach the vulnerable renderer`,
    );
  }
});

test("benign input is echoed verbatim by BOTH renderers", () => {
  // Documents the limitation of the signal: a plain-text value needs no
  // encoding, so "echoed raw" is not evidence of a problem on its own.
  assert.equal(renderProfileVulnerable("demo", "hello").inputEchoedRaw, true);
  assert.equal(renderProfileSecure("demo", "hello").inputEchoedRaw, true);
});

test("echoesInputRaw treats an empty input as not echoed", () => {
  assert.equal(echoesInputRaw("<p></p>", ""), false);
});

test("hasRawMarkup is a fragment check, not a document verdict", () => {
  assert.equal(hasRawMarkup("<b>bold</b>"), true);
  assert.equal(hasRawMarkup("plain text"), false);
});