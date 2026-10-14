// Test-support module: logic copied verbatim from src/components/AzraelEngine.tsx
// (tokenizeLine + its constants) so the pure helper can be unit-tested without
// pulling React rendering into scope. Keep in sync with the component source.

type TokenType = 'keyword' | 'type' | 'string' | 'comment' | 'number' | 'attribute' | 'function' | 'macro' | 'lifetime' | 'plain';

interface Token {
  text: string;
  type: TokenType;
}

const RUST_KEYWORDS = new Set([
  'use', 'pub', 'struct', 'trait', 'impl', 'fn', 'let', 'if', 'match',
  'return', 'unsafe', 'extern', 'const', 'mut', 'ref', 'self', 'Self',
  'mod', 'crate', 'super', 'where', 'for', 'in', 'loop', 'while',
  'break', 'continue', 'move', 'as', 'type', 'enum', 'dyn', 'static',
]);

const RUST_TYPES = new Set([
  'u8', 'u16', 'u32', 'u64', 'u128', 'usize', 'i8', 'i16', 'i32', 'i64',
  'i128', 'isize', 'f32', 'f64', 'bool', 'char', 'str', 'String',
  'Vec', 'Option', 'Result', 'Box', 'Arc', 'Rc', 'Ok', 'Err',
]);

function tokenizeLine(line: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;

  while (i < line.length) {
    // Comments
    if (line[i] === '/' && line[i + 1] === '/') {
      tokens.push({ text: line.slice(i), type: 'comment' });
      break;
    }

    // Attributes
    if (line[i] === '#' && line[i + 1] === '[') {
      const end = line.indexOf(']', i);
      const attrEnd = end === -1 ? line.length : end + 1;
      tokens.push({ text: line.slice(i, attrEnd), type: 'attribute' });
      i = attrEnd;
      continue;
    }

    // Strings
    if (line[i] === '"') {
      let end = i + 1;
      while (end < line.length && line[end] !== '"') {
        if (line[end] === '\\') end++;
        end++;
      }
      tokens.push({ text: line.slice(i, end + 1), type: 'string' });
      i = end + 1;
      continue;
    }

    // Numbers
    if (/\d/.test(line[i])) {
      let end = i;
      while (end < line.length && /[\dxXbBoO_]/.test(line[end])) end++;
      tokens.push({ text: line.slice(i, end), type: 'number' });
      i = end;
      continue;
    }

    // Lifetimes
    if (line[i] === '\'' && i + 1 < line.length && /[a-zA-Z]/.test(line[i + 1])) {
      let end = i + 1;
      while (end < line.length && /[a-zA-Z0-9_]/.test(line[end])) end++;
      tokens.push({ text: line.slice(i, end), type: 'lifetime' });
      i = end;
      continue;
    }

    // Words (keywords, types, identifiers)
    if (/[a-zA-Z_]/.test(line[i])) {
      let end = i;
      while (end < line.length && /[a-zA-Z0-9_]/.test(line[end])) end++;
      const word = line.slice(i, end);

      if (RUST_KEYWORDS.has(word)) {
        tokens.push({ text: word, type: 'keyword' });
      } else if (RUST_TYPES.has(word)) {
        tokens.push({ text: word, type: 'type' });
      } else if (end < line.length && line[end] === '!') {
        tokens.push({ text: word + '!', type: 'macro' });
      } else if (end < line.length && line[end] === '(') {
        tokens.push({ text: word, type: 'function' });
      } else {
        tokens.push({ text: word, type: 'plain' });
      }
      i = end;
      continue;
    }

    // Everything else (operators, punctuation, whitespace)
    tokens.push({ text: line[i], type: 'plain' });
    i++;
  }

  return tokens;
}

export { tokenizeLine };
export type { Token, TokenType };
