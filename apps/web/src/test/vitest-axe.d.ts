// Type augmentation for `vitest-axe`'s `toHaveNoViolations` matcher.
//
// `vitest-axe@0.1.0` ships its global type augmentation against the legacy
// `Vi.Assertion` namespace, which Vitest 2.x has retired in favor of the
// `Assertion` interface exported from `'vitest'`. As a result `tsc` doesn't
// see our `expect.extend({ toHaveNoViolations })` registration even though
// it works at runtime. This declaration file plugs the gap by augmenting
// the modern interface directly. WS-F2.

import 'vitest';

declare module 'vitest' {
  interface Assertion {
    toHaveNoViolations(): void;
  }
  interface AsymmetricMatchersContaining {
    toHaveNoViolations(): void;
  }
}
