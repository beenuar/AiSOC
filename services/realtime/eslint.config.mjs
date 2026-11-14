// ESLint for services/realtime.
//
// This service is published as a container image and had no CI at all — no
// build, no lint, no type-check, no test run. It is one of the two ends of
// the Kafka spine, it carries the OpenTelemetry instrumentation that makes
// the distributed trace continuous, and `src/index.ts` holds the TypeScript
// CORS guard enforcing the same wildcard-plus-credentials refusal as the
// vendored Python `cors.py` copies. A break here was found by whoever
// deployed it.
//
// Type-aware rules are on, because the defects that matter in a WebSocket and
// Kafka service are promise-shaped and none of them is visible without the
// type graph: a handler whose rejection nobody catches, an `async` callback
// passed where a synchronous `void` is expected — which silently drops the
// rejection — and an `await` on a value that was never a promise.
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.check.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // The `no-unsafe-*` family and `no-explicit-any` are off, and the
      // reason is recorded rather than left for a reader to guess: this
      // service's inputs are `JSON.parse` of a Kafka payload and of a Redis
      // pub/sub message. Those genuinely are `any` at the boundary. The rules
      // would be satisfied by asserting `as AlertEnvelope` over unvalidated
      // bytes, which converts an honest `any` into a type the compiler
      // believes and the wire does not guarantee — strictly worse than the
      // `any`, because it moves the failure from the boundary to wherever the
      // field is first dereferenced.
      //
      // The way to turn these back on is to parse the envelope through a
      // runtime validator so the narrowed type is earned. Until someone does
      // that, switching them on would only buy the assertions.
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/no-explicit-any': 'off',

      // kafkajs types `eachMessage` as `(payload) => Promise<void>`, so the
      // handler must be `async` whether or not its body happens to await
      // anything. The rule reads that as a redundant `async` when it is in
      // fact required by the callee's signature; dropping it would not
      // compile. The promise rules above still cover the real cases.
      '@typescript-eslint/require-await': 'off',
    },
  },
  {
    // `node:test` owns the promise its `test()` returns — the runner awaits
    // it and reports the failure. Flagging it as floating would be a false
    // positive on every case in the file, and the usual workaround (`void
    // test(...)`) suppresses the rule by discarding the handle the runner
    // needs. The rule stays on for `src`, which is where it finds real ones.
    files: ['test/**/*.ts'],
    rules: { '@typescript-eslint/no-floating-promises': 'off' },
  },
);
