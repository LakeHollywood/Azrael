// Pure helpers used by the STS dashboard components.
// Extracted from AzraelEngine.tsx / RiskMetrics.tsx so they are testable
// without a DOM and visible to mutation testing.

export function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

export function formatTelemetryValue(value, unit = "") {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return `-- ${unit}`.trim();
  }
  return `${value.toFixed(2)} ${unit}`.trim();
}

// FNV-1a variant producing a 16-hex-char digest; used as stable React keys
// and buffer dedupe tokens on the client side.
export function hashString(input) {
  let h1 = 0x811c9dc5 >>> 0;
  let h2 = 0x01000193 >>> 0;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ (c + i), 0x811c9dc5) >>> 0;
  }
  return (h1.toString(16).padStart(8, "0") +
          h2.toString(16).padStart(8, "0"));
}

export function nextBackoffDelay(current, cap) {
  if (current < 0) throw new RangeError("delay must be >= 0");
  return Math.min(current * 2, cap);
}
