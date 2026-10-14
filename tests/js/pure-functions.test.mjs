// Unit tests for pure helpers extracted from the React app.
// Run with: node --test tests/js/
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  clamp,
  formatTelemetryValue,
  hashString,
  nextBackoffDelay,
} from "./helpers.mjs";

test("clamp keeps values within bounds", () => {
  assert.equal(clamp(5, 0, 10), 5);
  assert.equal(clamp(-1, 0, 10), 0);
  assert.equal(clamp(99, 0, 10), 10);
});

test("formatTelemetryValue renders units and precision", () => {
  assert.equal(formatTelemetryValue(1.23456, "nT"), "1.23 nT");
  assert.equal(formatTelemetryValue(null, "nT"), "-- nT");
  assert.equal(formatTelemetryValue(NaN, "nT"), "-- nT");
});

test("hashString is deterministic and collision-resistant enough for keys", () => {
  const a = hashString("GOES_MAG:123.4");
  const b = hashString("GOES_MAG:123.4");
  const c = hashString("DSCOVR_MAG:123.4");
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.match(a, /^[0-9a-f]{16}$/);
});

test("nextBackoffDelay doubles and respects the cap", () => {
  assert.equal(nextBackoffDelay(1, 30), 2);
  assert.equal(nextBackoffDelay(16, 30), 30); // clamped to cap
  assert.equal(nextBackoffDelay(30, 30), 30); // stays at cap
});

test("nextBackoffDelay rejects negative input (policy: delay >= 0)", () => {
  assert.throws(() => nextBackoffDelay(-5, 30), RangeError);
});
