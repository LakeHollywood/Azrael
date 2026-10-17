import { describe, it, expect } from 'vitest';
import { tokenizeLine } from './extracted/tokenizeLine';

// Helper: concatenate token texts — the tokenizer must never lose characters.
const rejoin = (line: string) => tokenizeLine(line).map((t) => t.text).join('');

describe('tokenizeLine — losslessness', () => {
  const samples = [
    'use std::slice;',
    '#[repr(C)]',
    'pub struct AzraelContext {',
    'let x: u32 = 0xFF_00;',
    '// a comment with "quotes" and 123 numbers',
    'unsafe { slice::from_raw_parts(self.digest_ptr, self.digest_len) }',
    "'a",
    '',
    '   ',
  ];

  it.each(samples)('reconstructs %j exactly', (line) => {
    expect(rejoin(line)).toBe(line);
  });

  // KNOWN BUG (documented as of 2026-10-14): the macro branch pushes
  // `word + '!'` but never advances past the '!', so rejoining duplicates
  // the bang and lines containing macros do NOT round-trip losslessly.
  it('KNOWN BUG: macro lines duplicate "!" when rejoined', () => {
    const line = 'println!("bound {}", id);';
    expect(rejoin(line)).toBe('println!!("bound {}", id);');
  });
});

describe('tokenizeLine — token classification', () => {
  it('classifies Rust keywords', () => {
    const tokens = tokenizeLine('pub fn main() {}');
    expect(tokens[0]).toEqual({ text: 'pub', type: 'keyword' });
    expect(tokens).toContainEqual({ text: 'fn', type: 'keyword' });
  });

  it('classifies primitive/stdlib types', () => {
    const tokens = tokenizeLine('let v: Vec<u8> = Box::new();');
    expect(tokens).toContainEqual({ text: 'Vec', type: 'type' });
    expect(tokens).toContainEqual({ text: 'u8', type: 'type' });
    expect(tokens).toContainEqual({ text: 'Box', type: 'type' });
  });

  it('treats an entire // line suffix as one comment token', () => {
    const tokens = tokenizeLine('code(); // trailing note 42');
    const comment = tokens.find((t) => t.type === 'comment');
    expect(comment).toEqual({ text: '// trailing note 42', type: 'comment' });
    expect(tokens.indexOf(comment!)).toBeGreaterThan(0);
  });

  it('handles a line that starts with a comment', () => {
    const tokens = tokenizeLine('// only a comment');
    expect(tokens).toHaveLength(1);
    expect(tokens[0].type).toBe('comment');
  });

  it('captures attributes including the closing bracket', () => {
    const tokens = tokenizeLine('#[repr(C)]');
    expect(tokens[0]).toEqual({ text: '#[repr(C)]', type: 'attribute' });
  });

  it('handles unterminated attribute gracefully', () => {
    const tokens = tokenizeLine('#[no closing bracket');
    expect(tokens[0].type).toBe('attribute');
    expect(rejoin('#[no closing bracket')).toBe('#[no closing bracket');
  });

  it('keeps strings (with escapes) as single tokens', () => {
    const tokens = tokenizeLine('let s = "hello \\"world\\"";');
    const strTok = tokens.find((t) => t.type === 'string');
    expect(strTok!.text).toBe('"hello \\"world\\""');
  });

  it('classifies numeric literals incl. radix prefixes and underscores', () => {
    // The number branch matches [\dxXbBoO_], so uppercase hex letters (F) end
    // a literal mid-way — documented current behavior, not ideal Rust lexing.
    const tokens = tokenizeLine('0x1F_0B 42 0b1010 0o77');
    const nums = tokens.filter((t) => t.type === 'number').map((t) => t.text);
    expect(nums).toEqual(['0x1', '42', '0b1010', '0o77']);
  });

  it('classifies lifetimes', () => {
    const tokens = tokenizeLine("fn f<'a>(x: &'a str)");
    const lifetimes = tokens.filter((t) => t.type === 'lifetime').map((t) => t.text);
    expect(lifetimes).toContain("'a");
  });

  it('does not misclassify char literal start when next char is punctuation', () => {
    // '\'' followed by non-letter should NOT become a lifetime
    const tokens = tokenizeLine("' x");
    expect(tokens.some((t) => t.type === 'lifetime')).toBe(false);
  });

  it('classifies macros by trailing bang', () => {
    const tokens = tokenizeLine('println!("hi");');
    expect(tokens[0]).toEqual({ text: 'println!', type: 'macro' });
  });

  it('classifies identifiers followed by ( as functions', () => {
    const tokens = tokenizeLine('ct_eq(actual, expected)');
    expect(tokens[0]).toEqual({ text: 'ct_eq', type: 'function' });
  });

  it('falls back to plain for unknown identifiers', () => {
    const tokens = tokenizeLine('azrael_context');
    expect(tokens[0]).toEqual({ text: 'azrael_context', type: 'plain' });
  });

  it('emits single-char plain tokens for operators/punctuation', () => {
    const tokens = tokenizeLine('& 0x01 == 0');
    const amps = tokens.filter((t) => t.text === '&');
    expect(amps).toHaveLength(1);
    expect(amps[0].type).toBe('plain');
  });
});
