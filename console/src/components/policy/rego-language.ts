import { StreamLanguage, type StreamParser } from '@codemirror/language';

const KEYWORDS = new Set([
  'package',
  'import',
  'default',
  'if',
  'else',
  'not',
  'with',
  'some',
  'every',
  'in',
  'as',
  'contains',
  'true',
  'false',
  'null',
]);

const BUILTINS = new Set([
  'count',
  'split',
  'concat',
  'startswith',
  'endswith',
  'to_number',
  'regex',
  'array',
  'object',
  'json',
  'sprintf',
  'trim',
  'lower',
  'upper',
  'input',
  'data',
  'allow',
]);

interface RegoState {
  inRawString: boolean;
}

/** Small tokenizer for OPA Rego, enough for readable highlighting in the policy editor. */
const regoParser: StreamParser<RegoState> = {
  startState: () => ({ inRawString: false }),
  token(stream, state) {
    if (state.inRawString) {
      if (stream.skipTo('`')) {
        stream.next();
        state.inRawString = false;
      } else {
        stream.skipToEnd();
      }
      return 'string';
    }
    if (stream.eatSpace()) return null;
    if (stream.match('#')) {
      stream.skipToEnd();
      return 'comment';
    }
    if (stream.match('`')) {
      state.inRawString = true;
      return 'string';
    }
    if (stream.match(/^"(?:[^"\\]|\\.)*"/)) return 'string';
    if (stream.match(/^-?\d+(\.\d+)?([eE][+-]?\d+)?/)) return 'number';
    if (stream.match(/^(:=|==|!=|<=|>=|\|\||&&|[-+*/%<>=|&!])/)) return 'operator';
    if (stream.match(/^[{}[\]().,;:]/)) return 'punctuation';
    if (stream.match(/^\$?[A-Za-z_][A-Za-z0-9_]*/)) {
      const word = stream.current();
      if (KEYWORDS.has(word)) return 'keyword';
      if (BUILTINS.has(word)) return 'variableName.special';
      if (stream.peek() === '(') return 'variableName.function';
      return 'variableName';
    }
    stream.next();
    return null;
  },
};

export function regoLanguage() {
  return StreamLanguage.define(regoParser);
}
