/**
 * The editor must be able to author every step type the engine runs.
 *
 * This directory declared its own nine-member `StepType` union while the
 * engine declared twenty-two and `packages/types` published twenty-two. The
 * build stayed green because `STEP_SCHEMAS` was keyed `Record<StepType, …>`
 * on the *local* union, so exhaustiveness was satisfied by the nine that
 * existed — thirteen verbs the product could run had no way to be authored,
 * and nothing said so.
 *
 * The union is now imported, so the compiler catches the next one. These
 * tests cover what the compiler cannot: that the published file really does
 * still hold the union being imported (a rename would leave both sides
 * agreeing on the wrong thing), that no entry is a placeholder, and that the
 * one type the engine cannot run is presented as such rather than offered.
 *
 * `scripts/check_playbook_schema_parity.py` is the other half — it reads the
 * engine, the JSON schema, the published package and this directory, in both
 * directions. This file is the half that can execute the registry.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StepType } from './types';
import {
  ALL_STEP_TYPES,
  AUTHORABLE_STEP_TYPES,
  STEP_SCHEMAS,
  defaultParamsFor,
  validateStepFields,
} from './stepSchemas';
import { STEP_TYPE_META } from './stepColors';

/**
 * One set of parameters that makes a step of each type valid.
 *
 * Exhaustive by construction. `approval` is present and empty because there
 * is nothing that makes it valid — the test that asserts so reads this too.
 */
const VALID_PARAMS: Record<StepType, Record<string, unknown>> = {
  enrich: { indicator_field: 'alert.src_ip' },
  investigate: { case_id_field: 'alert.case_id' },
  notify: { message_template: 'Lateral movement on {{alert.host}}' },
  block_ip: { ip_field: 'alert.src_ip' },
  block_ioc: { ioc: '203.0.113.10', ioc_type: 'IpAddress' },
  isolate_host: { host_field: 'alert.host' },
  create_ticket: { title_template: 'Credential access on {{alert.host}}' },
  close_case: {},
  http: { url: 'https://example.com/hook' },
  condition: {},
  osquery_live_query: { template: 'running_processes' },
  approval: {},
  disable_user: { user: 'jane.doe@example.com' },
  reset_password: { user: 'jane.doe@example.com' },
  revoke_session: { user: 'jane.doe@example.com' },
  force_mfa: { user: 'jane.doe@example.com' },
  kill_process: { host: 'web-prod-04', pid: 4821 },
  quarantine_file: { host: 'web-prod-04', file_path: 'C:/temp/svchost.exe' },
  run_av_scan: { host: 'web-prod-04' },
  run_script: { host: 'web-prod-04', script_name: 'collect-persistence' },
  search_siem: { query: 'index=proxy dest_ip=203.0.113.10' },
  create_notable_event: { title: 'Credential access on web-prod-04' },
};

/**
 * The first key `engine._resolve_target` looks for, per governed verb, or
 * `null` where the verb has no scalar target and its details ride in params.
 *
 * A form collecting `user_field` writes a key nothing dereferences, which is
 * how a step ends up dispatching with an empty target. The two marked as
 * pre-existing keep the `*_field` convention the 833 shipped steps are
 * written in; see the header of `stepSchemas.ts`.
 */
const TARGET_KEY: Record<StepType, string | null> = {
  enrich: null,
  investigate: null,
  notify: null,
  close_case: null,
  http: null,
  condition: null,
  osquery_live_query: null,
  approval: null,
  block_ip: 'ip_field', // pre-existing convention
  isolate_host: 'host_field', // pre-existing convention
  create_ticket: 'title_template', // no scalar target; details ride in params
  block_ioc: 'ioc',
  kill_process: 'host',
  quarantine_file: 'host',
  run_av_scan: 'host',
  run_script: 'host',
  disable_user: 'user',
  reset_password: 'user',
  revoke_session: 'user',
  force_mfa: 'user',
  search_siem: 'query',
  create_notable_event: 'title',
};

/**
 * The `StepType` union as published, read from source.
 *
 * Parsed rather than imported because a TypeScript union does not exist at
 * runtime — and parsing is the point: it proves the file the editor imports
 * from still declares what the editor thinks it does.
 */
function publishedStepTypes(): string[] {
  const path = join(__dirname, '../../../../../packages/types/src/playbook.ts');
  const source = readFileSync(path, 'utf8');
  const start = source.indexOf('export type StepType =');
  expect(start, `no StepType union in ${path}`).toBeGreaterThan(-1);
  const body = source.slice(start, source.indexOf(';', start));
  const members = [...body.matchAll(/\|\s*"([a-z_]+)"/g)].map((m) => m[1]);
  expect(members.length, 'the published union parsed to nothing').toBeGreaterThan(0);
  return members;
}

describe('the editor step vocabulary', () => {
  it('offers a form for every step type the published package declares', () => {
    const published = publishedStepTypes();
    expect([...ALL_STEP_TYPES].sort()).toEqual([...published].sort());
  });

  it('declares nothing the published package does not', () => {
    const published = new Set(publishedStepTypes());
    for (const type of ALL_STEP_TYPES) {
      expect(published.has(type), `${type} is not a published step type`).toBe(true);
    }
  });

  it('gives every type canvas and palette presentation', () => {
    for (const type of ALL_STEP_TYPES) {
      expect(STEP_TYPE_META[type], `no canvas metadata for ${type}`).toBeDefined();
      expect(STEP_TYPE_META[type].label).toBe(STEP_SCHEMAS[type].label);
    }
  });

  it('gives every type a label, a description and an execution class', () => {
    for (const type of ALL_STEP_TYPES) {
      const schema = STEP_SCHEMAS[type];
      expect(schema.type, `${type}: the key and the declared type disagree`).toBe(type);
      expect(schema.label.trim().length, `${type}: empty label`).toBeGreaterThan(0);
      expect(
        schema.description.trim().length,
        `${type}: empty description`,
      ).toBeGreaterThan(20);
      expect(['executed', 'governed', 'unimplemented']).toContain(schema.execution);
    }
  });

  it('never asks an author to paste a credential into a playbook', () => {
    // Credentials are resolved per tenant from the connector vault by
    // `services/api` at dispatch. A form collecting `cs_client_secret` would
    // be putting a secret in a document that gets exported and shared.
    const secretish = /(secret|password|token|api_key|client_id|credential)/i;
    for (const type of ALL_STEP_TYPES) {
      for (const field of STEP_SCHEMAS[type].fields) {
        // `send_email` and `reset_password`'s own label mention passwords
        // without collecting one; the key is what ends up in the document.
        expect(
          secretish.test(field.key),
          `${type}.${field.key} looks like a credential`,
        ).toBe(false);
      }
    }
  });
});

describe('a type the engine cannot run', () => {
  const unrunnable = ALL_STEP_TYPES.filter(
    (t) => STEP_SCHEMAS[t].execution === 'unimplemented',
  );

  it('is still known to the editor, so an imported playbook can be read', () => {
    // Not asserted to be `approval` specifically: the property worth holding
    // is that whatever is unrunnable is handled this way.
    expect(unrunnable.length).toBeGreaterThan(0);
    for (const type of unrunnable) {
      expect(STEP_SCHEMAS[type]).toBeDefined();
      expect(STEP_TYPE_META[type]).toBeDefined();
    }
  });

  it('is not offered as something to add', () => {
    for (const type of unrunnable) {
      expect(AUTHORABLE_STEP_TYPES).not.toContain(type);
    }
    // ...and everything else is.
    expect(AUTHORABLE_STEP_TYPES.length).toBe(
      ALL_STEP_TYPES.length - unrunnable.length,
    );
  });

  it('says why, rather than implying it will execute', () => {
    for (const type of unrunnable) {
      const schema = STEP_SCHEMAS[type];
      expect(schema.unavailable, `${type} has no reason recorded`).toBeTruthy();
      expect(schema.unavailable!.length).toBeGreaterThan(80);
      // The engine fails the step and the default policy aborts the run. The
      // editor has to say that, not hint at it.
      expect(schema.description.toLowerCase()).toContain('not runnable');
    }
  });

  it('reports the step as invalid so the author is told before they save', () => {
    for (const type of unrunnable) {
      const errors = validateStepFields(type, defaultParamsFor(type));
      expect(errors.length).toBeGreaterThan(0);
      expect(errors.some((e) => /not runnable/i.test(e.message))).toBe(true);
    }
  });

  it('carries no fields, so there is nothing to fill in that would do anything', () => {
    for (const type of unrunnable) {
      expect(STEP_SCHEMAS[type].fields).toHaveLength(0);
    }
  });
});

describe('a runnable type', () => {
  const runnable = ALL_STEP_TYPES.filter(
    (t) => STEP_SCHEMAS[t].execution !== 'unimplemented',
  );

  it('records no "unavailable" reason, which is reserved for what cannot run', () => {
    for (const type of runnable) {
      expect(STEP_SCHEMAS[type].unavailable).toBeUndefined();
    }
  });

  it('validates clean once its required fields are filled', () => {
    // A form that cannot produce a valid step is worse than the type being
    // absent, so every schema must have at least one set of inputs that
    // passes its own validator.
    //
    // Keyed on the full `StepType` so the compiler demands an entry for a new
    // verb. A `Partial<>` here would have been a sixth partial vocabulary in
    // a file written to stop there being a fifth.
    for (const type of runnable) {
      const params = { ...defaultParamsFor(type), ...VALID_PARAMS[type] };
      expect(validateStepFields(type, params), `${type} cannot be made valid`).toEqual(
        [],
      );
    }
  });
});

describe('the governed response verbs', () => {
  const governed = ALL_STEP_TYPES.filter(
    (t) => STEP_SCHEMAS[t].execution === 'governed',
  );

  it('collect a target under a key the engine resolves', () => {
    for (const type of governed) {
      const expected = TARGET_KEY[type];
      expect(expected, `${type} is governed and has no recorded target key`).not.toBeNull();
      const keys = STEP_SCHEMAS[type].fields.map((f) => f.key);
      expect(keys, `${type} does not collect ${expected}`).toContain(expected);
    }
  });

  it('offers no dry-run control, because nothing reads one', () => {
    // Whether a vendor is touched is decided by
    // `AISOC_PLAYBOOK_ACTIONS_EXECUTE` and the capability contract, not by a
    // param on the step. The shipped packs carry `dry_run` and the bridge
    // ignores it; a checkbox here would be a control that does nothing.
    for (const type of governed) {
      const keys = STEP_SCHEMAS[type].fields.map((f) => f.key);
      expect(keys, `${type} offers an inert dry_run control`).not.toContain('dry_run');
    }
  });
});
