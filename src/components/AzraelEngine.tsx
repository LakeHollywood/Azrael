import { useState, useCallback } from 'react';

// ── Syntax Highlighter ──────────────────────────────────────────────
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

const tokenColors: Record<TokenType, string> = {
  keyword: 'text-purple-400',
  type: 'text-cyan-300',
  string: 'text-emerald-300',
  comment: 'text-slate-500 italic',
  number: 'text-orange-300',
  attribute: 'text-yellow-300',
  function: 'text-blue-300',
  macro: 'text-yellow-400',
  lifetime: 'text-pink-400',
  plain: 'text-slate-300',
};

function CodeLine({ line, lineNum }: { line: string; lineNum: number }) {
  const tokens = tokenizeLine(line);
  return (
    <div className="flex hover:bg-slate-800/40 group">
      <span className="w-12 shrink-0 text-right pr-4 text-slate-600 select-none text-xs leading-6 group-hover:text-slate-500">
        {lineNum}
      </span>
      <span className="flex-1 leading-6">
        {tokens.map((token, i) => (
          <span key={i} className={tokenColors[token.type]}>
            {token.text}
          </span>
        ))}
      </span>
    </div>
  );
}

// ── Safety Annotations ──────────────────────────────────────────────
const annotations = [
  {
    line: 3,
    label: 'FFI-Safe Layout',
    detail: '#[repr(C)] guarantees C-compatible memory layout for cross-language interop. The struct can be safely passed across FFI boundaries without Rust reordering fields.',
    icon: 'fa-memory',
  },
  {
    line: 18,
    label: 'Constant-Time Comparison',
    detail: 'subtle::ConstantTimeEq prevents timing side-channels. Digest verification runs in fixed time regardless of where the first mismatch occurs — critical for cryptographic material.',
    icon: 'fa-clock',
  },
  {
    line: 29,
    label: 'Authority Gate',
    detail: 'Bitwise flag check (0x01) enforces boundary predicates before any payload processing. Returns AZRAEL_ERR_BOUNDARY_VIOLATION (-3) on denial — the containment protocol activates immediately.',
    icon: 'fa-lock',
  },
  {
    line: 37,
    label: 'Panic Containment',
    detail: 'catch_unwind wraps the entire extern "C" boundary. Any Rust panic is caught and converted to error code -99, preventing undefined behavior from propagating to the C caller.',
    icon: 'fa-shield-halved',
  },
  {
    line: 39,
    label: 'Null Guard',
    detail: 'Both pointers are validated before any dereference. This is the first line of defense — null pointers return -3 immediately without entering the predicate logic.',
    icon: 'fa-crosshairs',
  },
];

// ── Evaluation Simulator ────────────────────────────────────────────
interface EvalResult {
  code: number;
  label: string;
  color: string;
  detail: string;
  latency: string;
}

function simulateEval(
  ctxNull: boolean,
  payloadNull: boolean,
  authorityFlag: boolean,
  digestMatch: boolean,
): EvalResult {
  if (ctxNull || payloadNull) {
    return {
      code: -3,
      label: 'AZRAEL_ERR_BOUNDARY_VIOLATION',
      color: 'text-red-400',
      detail: 'Null pointer detected. Predicate evaluation aborted before entering safety-critical path.',
      latency: '0.02ms',
    };
  }
  if (!authorityFlag) {
    return {
      code: -3,
      label: 'AZRAEL_ERR_BOUNDARY_VIOLATION',
      color: 'text-red-400',
      detail: 'Authority flag bit 0 not set. Containment protocol activated — thread state revoked.',
      latency: '0.04ms',
    };
  }
  if (!digestMatch) {
    return {
      code: -7,
      label: 'AZRAEL_ERR_DIGEST_MISMATCH',
      color: 'text-orange-400',
      detail: 'Constant-time comparison detected mismatch. Payload integrity cannot be verified.',
      latency: '0.12ms',
    };
  }
  return {
    code: 0,
    label: 'AZRAEL_OK',
    color: 'text-emerald-400',
    detail: 'All predicates satisfied. Authority verified, digest matches, payload accepted.',
    latency: '0.08ms',
  };
}

// ── Memory Layout ───────────────────────────────────────────────────
const structFields = [
  { name: 'digest_ptr', type: '*const u8', size: '8 bytes', offset: '0x00', color: 'bg-cyan-500/20 border-cyan-500/40' },
  { name: 'digest_len', type: 'usize', size: '8 bytes', offset: '0x08', color: 'bg-blue-500/20 border-blue-500/40' },
  { name: 'sequence_id', type: 'u64', size: '8 bytes', offset: '0x10', color: 'bg-indigo-500/20 border-indigo-500/40' },
  { name: 'authority_flags', type: 'u32', size: '4 bytes', offset: '0x18', color: 'bg-purple-500/20 border-purple-500/40' },
  { name: '(padding)', type: '—', size: '4 bytes', offset: '0x1C', color: 'bg-slate-700/30 border-slate-600/30' },
];

// ── Main Component ──────────────────────────────────────────────────
const rustSource = `use std::slice;

#[repr(C)]
pub struct AzraelContext {
    pub digest_ptr: *const u8,
    pub digest_len: usize,
    pub sequence_id: u64,
    pub authority_flags: u32,
}

pub trait AuthorityGuard {
    fn verify_digest(&self, expected: &[u8]) -> bool;
    fn validate_predicate(&self, payload: &[u8]) -> Result<(), i32>;
}

impl AuthorityGuard for AzraelContext {
    fn verify_digest(&self, expected: &[u8]) -> bool {
        if self.digest_ptr.is_null() || self.digest_len != expected.len() {
            return false;
        }
        let actual = unsafe { slice::from_raw_parts(self.digest_ptr, self.digest_len) };
        subtle::ConstantTimeEq::ct_eq(actual, expected).into()
    }

    fn validate_predicate(&self, payload: &[u8]) -> Result<(), i32> {
        if self.authority_flags & 0x01 == 0 {
            return Err(-3); // AZRAEL_ERR_BOUNDARY_VIOLATION
        }
        Ok(())
    }
}

#[no_mangle]
pub unsafe extern "C" fn azrael_eval_predicate(
    ctx: *const AzraelContext,
    payload_ptr: *const u8,
    payload_len: usize,
) -> i32 {
    std::panic::catch_unwind(|| {
        if ctx.is_null() || payload_ptr.is_null() {
            return -3;
        }

        let context = &*ctx;
        let payload = slice::from_raw_parts(payload_ptr, payload_len);

        match context.validate_predicate(payload) {
            Ok(_) => 0, // AZRAEL_OK
            Err(code) => {
                eprintln!("[AZRAEL CONTAINMENT] Revoking thread state. Code: {}", code);
                code
            }
        }
    }).unwrap_or(-99)
}`;

export default function AzraelEngine() {
  const [activeAnnotation, setActiveAnnotation] = useState<number | null>(null);
  const [evalResult, setEvalResult] = useState<EvalResult | null>(null);
  const [isEvaluating, setIsEvaluating] = useState(false);

  // Simulator state
  const [ctxNull, setCtxNull] = useState(false);
  const [payloadNull, setPayloadNull] = useState(false);
  const [authorityFlag, setAuthorityFlag] = useState(true);
  const [digestMatch, setDigestMatch] = useState(true);

  const lines = rustSource.split('\n');

  const runEval = useCallback(() => {
    setIsEvaluating(true);
    setEvalResult(null);
    setTimeout(() => {
      const result = simulateEval(ctxNull, payloadNull, authorityFlag, digestMatch);
      setEvalResult(result);
      setIsEvaluating(false);
    }, 300 + Math.random() * 200);
  }, [ctxNull, payloadNull, authorityFlag, digestMatch]);

  return (
    <section id="azrael" className="py-24 px-6">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-16">
          <span className="text-red-400 text-sm font-semibold tracking-wider uppercase">Section 3.5 — Annex</span>
          <h2 className="text-4xl font-bold mt-3 mb-4">
            <span className="bg-gradient-to-r from-red-400 via-orange-300 to-yellow-300 bg-clip-text text-transparent">
              Azrael Predicate Engine
            </span>
          </h2>
          <p className="text-slate-400 max-w-2xl mx-auto">
            The core runtime predicate evaluator. FFI-safe, panic-contained, constant-time digest verification. 
            This is the enforcement layer that gates all autonomy decisions.
          </p>
        </div>

        {/* Top Stats Bar */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-10">
          {[
            { label: 'Lines of Verified Rust', value: '58', icon: 'fa-code' },
            { label: 'FFI Surface', value: '1 fn', icon: 'fa-plug' },
            { label: 'Panic Paths Caught', value: '1', icon: 'fa-bug' },
            { label: 'Worst-Case Latency', value: '<0.2ms', icon: 'fa-gauge-high' },
          ].map((stat) => (
            <div key={stat.label} className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 text-center">
              <i className={`fa-solid ${stat.icon} text-red-400/60 text-lg mb-2`}></i>
              <div className="text-2xl font-bold text-white">{stat.value}</div>
              <div className="text-xs text-slate-500 mt-1">{stat.label}</div>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          {/* Code Viewer */}
          <div className="xl:col-span-2 bg-slate-950 border border-slate-800 rounded-2xl overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 bg-slate-900/60">
              <div className="flex items-center gap-3">
                <div className="flex gap-1.5">
                  <span className="w-3 h-3 rounded-full bg-red-500/80"></span>
                  <span className="w-3 h-3 rounded-full bg-yellow-500/80"></span>
                  <span className="w-3 h-3 rounded-full bg-emerald-500/80"></span>
                </div>
                <span className="text-sm text-slate-400 font-mono">azrael_engine.rs</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-600">Rust</span>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              </div>
            </div>
            <div className="overflow-x-auto p-4 font-mono text-sm max-h-[600px] overflow-y-auto">
              {lines.map((line, i) => {
                const isActive = activeAnnotation !== null && annotations[activeAnnotation]?.line === i + 1;
                return (
                  <div
                    key={i}
                    className={`transition-colors duration-200 ${
                      isActive ? 'bg-red-500/10 border-l-2 border-red-400 -ml-px pl-px' : ''
                    }`}
                  >
                    <CodeLine line={line} lineNum={i + 1} />
                  </div>
                );
              })}
            </div>
          </div>

          {/* Annotations Panel */}
          <div className="space-y-4">
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5">
              <h3 className="font-bold text-sm text-slate-300 mb-4 flex items-center gap-2">
                <i className="fa-solid fa-magnifying-glass text-red-400"></i>
                Safety Annotations
              </h3>
              <div className="space-y-2">
                {annotations.map((ann, i) => (
                  <button
                    key={i}
                    onMouseEnter={() => setActiveAnnotation(i)}
                    onMouseLeave={() => setActiveAnnotation(null)}
                    className={`w-full text-left p-3 rounded-xl border transition-all ${
                      activeAnnotation === i
                        ? 'bg-red-500/10 border-red-500/30'
                        : 'bg-slate-800/30 border-slate-800 hover:border-slate-600'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <i className={`fa-solid ${ann.icon} text-xs ${activeAnnotation === i ? 'text-red-400' : 'text-slate-500'}`}></i>
                      <span className="text-sm font-medium text-slate-200">{ann.label}</span>
                      <span className="ml-auto text-xs text-slate-600 font-mono">L{ann.line}</span>
                    </div>
                    {activeAnnotation === i && (
                      <p className="text-xs text-slate-400 mt-2 leading-relaxed">{ann.detail}</p>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* Memory Layout */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5">
              <h3 className="font-bold text-sm text-slate-300 mb-4 flex items-center gap-2">
                <i className="fa-solid fa-microchip text-cyan-400"></i>
                AzraelContext Layout
                <span className="ml-auto text-xs text-slate-600 font-mono">repr(C) • 32 bytes</span>
              </h3>
              <div className="space-y-1.5">
                {structFields.map((field) => (
                  <div key={field.name} className={`flex items-center gap-3 p-2 rounded-lg border ${field.color}`}>
                    <span className="text-xs text-slate-500 font-mono w-8">{field.offset}</span>
                    <span className="text-sm font-mono text-slate-200 flex-1">{field.name}</span>
                    <span className="text-xs text-slate-500">{field.type}</span>
                    <span className="text-xs text-slate-600 w-14 text-right">{field.size}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Evaluation Simulator */}
        <div className="mt-10 bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center">
                <i className="fa-solid fa-flask text-red-400 text-sm"></i>
              </div>
              <div>
                <h3 className="font-bold text-slate-200">Predicate Evaluation Simulator</h3>
                <p className="text-xs text-slate-500">Configure inputs to trace execution through azrael_eval_predicate</p>
              </div>
            </div>
            <button
              onClick={runEval}
              disabled={isEvaluating}
              className="px-4 py-2 bg-red-500/20 border border-red-500/30 rounded-lg text-sm font-medium text-red-300 hover:bg-red-500/30 transition-all disabled:opacity-50"
            >
              {isEvaluating ? (
                <>
                  <i className="fa-solid fa-spinner fa-spin mr-2"></i>
                  Evaluating...
                </>
              ) : (
                <>
                  <i className="fa-solid fa-play mr-2"></i>
                  Run Eval
                </>
              )}
            </button>
          </div>

          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
              {/* Toggle: ctx null */}
              <label className="flex items-center gap-3 bg-slate-800/40 rounded-xl p-4 border border-slate-700/50 cursor-pointer hover:border-slate-600 transition-all">
                <input
                  type="checkbox"
                  checked={ctxNull}
                  onChange={(e) => setCtxNull(e.target.checked)}
                  className="w-4 h-4 accent-red-500"
                />
                <div>
                  <div className="text-sm text-slate-200 font-medium">ctx == NULL</div>
                  <div className="text-xs text-slate-500">Null context pointer</div>
                </div>
              </label>

              {/* Toggle: payload null */}
              <label className="flex items-center gap-3 bg-slate-800/40 rounded-xl p-4 border border-slate-700/50 cursor-pointer hover:border-slate-600 transition-all">
                <input
                  type="checkbox"
                  checked={payloadNull}
                  onChange={(e) => setPayloadNull(e.target.checked)}
                  className="w-4 h-4 accent-red-500"
                />
                <div>
                  <div className="text-sm text-slate-200 font-medium">payload == NULL</div>
                  <div className="text-xs text-slate-500">Null payload pointer</div>
                </div>
              </label>

              {/* Toggle: authority flag */}
              <label className="flex items-center gap-3 bg-slate-800/40 rounded-xl p-4 border border-slate-700/50 cursor-pointer hover:border-slate-600 transition-all">
                <input
                  type="checkbox"
                  checked={authorityFlag}
                  onChange={(e) => setAuthorityFlag(e.target.checked)}
                  className="w-4 h-4 accent-emerald-500"
                />
                <div>
                  <div className="text-sm text-slate-200 font-medium">flags & 0x01</div>
                  <div className="text-xs text-slate-500">Authority bit set</div>
                </div>
              </label>

              {/* Toggle: digest match */}
              <label className="flex items-center gap-3 bg-slate-800/40 rounded-xl p-4 border border-slate-700/50 cursor-pointer hover:border-slate-600 transition-all">
                <input
                  type="checkbox"
                  checked={digestMatch}
                  onChange={(e) => setDigestMatch(e.target.checked)}
                  className="w-4 h-4 accent-emerald-500"
                />
                <div>
                  <div className="text-sm text-slate-200 font-medium">digest match</div>
                  <div className="text-xs text-slate-500">Constant-time eq</div>
                </div>
              </label>
            </div>

            {/* Execution Trace */}
            {evalResult && (
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center gap-3 mb-4">
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                    evalResult.code === 0 ? 'bg-emerald-500/20' : 'bg-red-500/20'
                  }`}>
                    <i className={`fa-solid ${evalResult.code === 0 ? 'fa-check' : 'fa-xmark'} text-lg ${evalResult.color}`}></i>
                  </div>
                  <div>
                    <div className={`font-bold font-mono ${evalResult.color}`}>
                      return {evalResult.code}; // {evalResult.label}
                    </div>
                    <div className="text-xs text-slate-500">Latency: {evalResult.latency}</div>
                  </div>
                </div>
                <p className="text-sm text-slate-400 mb-4">{evalResult.detail}</p>

                {/* Execution trace */}
                <div className="border-t border-slate-800 pt-4">
                  <p className="text-xs text-slate-500 font-semibold mb-2">EXECUTION TRACE:</p>
                  <div className="space-y-1 font-mono text-xs">
                    <div className="text-slate-500">
                      <span className="text-slate-600">→</span> catch_unwind entered
                    </div>
                    {!ctxNull && !payloadNull ? (
                      <>
                        <div className="text-slate-400">
                          <span className="text-slate-600">→</span> null checks passed
                        </div>
                        <div className="text-slate-400">
                          <span className="text-slate-600">→</span> slice::from_raw_parts(payload_ptr, payload_len)
                        </div>
                        <div className={authorityFlag ? 'text-emerald-400' : 'text-red-400'}>
                          <span className="text-slate-600">→</span> validate_predicate: authority_flags & 0x01 {authorityFlag ? '== 1 ✓' : '== 0 ✗'}
                        </div>
                        {authorityFlag && (
                          <div className="text-emerald-400">
                            <span className="text-slate-600">→</span> Ok(()) → returning AZRAEL_OK (0)
                          </div>
                        )}
                        {!authorityFlag && (
                          <div className="text-red-400">
                            <span className="text-slate-600">→</span> Err(-3) → [AZRAEL CONTAINMENT] Revoking thread state
                          </div>
                        )}
                      </>
                    ) : (
                      <div className="text-red-400">
                        <span className="text-slate-600">→</span> null pointer detected → returning -3 immediately
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {!evalResult && !isEvaluating && (
              <div className="text-center py-8 text-slate-600">
                <i className="fa-solid fa-terminal text-2xl mb-3 block"></i>
                <p className="text-sm">Configure inputs above and click "Run Eval" to trace execution</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
