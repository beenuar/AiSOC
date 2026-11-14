#!/usr/bin/env node
/**
 * Tiny CLI dispatcher.
 *
 *   aisoc-connector dev <file.ts> [--port=7311] [--no-watch]
 *   aisoc-connector init <name>
 *   aisoc-connector manifest <file.ts>
 *
 * The cli re-uses the runtime SDK; we don't ship an extra commander
 * dep because the surface is too small to warrant it.
 */
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve, basename, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(HERE, '..');

const [cmd, ...rest] = process.argv.slice(2);

function fail(msg) {
  process.stderr.write(msg + '\n');
  process.exit(2);
}

function help() {
  process.stderr.write(
    [
      'aisoc-connector — TypeScript Connector SDK CLI',
      '',
      'Commands:',
      '  dev <file>        Start the hot-reload dev server',
      '  init <name>       Scaffold a new connector in ./<name>/',
      '  manifest <file>   Print the JSON manifest for <file> to stdout',
      '',
    ].join('\n'),
  );
}

function runDev(args) {
  const file = args[0];
  if (!file) fail('aisoc-connector dev <file.ts> — file is required');
  const target = resolve(PKG_ROOT, 'src', 'dev.ts');
  const child = spawn(
    'npx',
    ['tsx', target, file, ...args.slice(1)],
    { stdio: 'inherit', shell: false },
  );
  child.on('exit', (code) => process.exit(code ?? 0));
}

function runManifest(args) {
  const file = args[0];
  if (!file) fail('aisoc-connector manifest <file.ts> — file is required');
  // Use tsx --eval to avoid building. Importing the file gives us
  // its default export which we feed into manifestForConnector.
  const tsxExpr = `
    import { manifestForConnector } from '${PKG_ROOT.replace(/\\/g, '/')}/src/index.ts';
    const mod = await import('${resolve(file).replace(/\\/g, '/')}');
    process.stdout.write(JSON.stringify(manifestForConnector(mod.default), null, 2));
  `;
  const child = spawn('npx', ['tsx', '--eval', tsxExpr], {
    stdio: 'inherit',
    shell: false,
  });
  child.on('exit', (code) => process.exit(code ?? 0));
}

function runInit(args) {
  const name = args[0];
  if (!name || !/^[a-z0-9][a-z0-9-]{1,40}$/.test(name)) {
    fail(
      'aisoc-connector init <name> — name must be 2-41 chars, ' +
        'lowercase letters/digits/hyphens',
    );
  }
  const dir = resolve(process.cwd(), name);
  if (existsSync(dir)) fail(`refusing to overwrite ${dir}`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    resolve(dir, 'package.json'),
    JSON.stringify(
      {
        name: `@aisoc-connectors/${name}`,
        version: '0.1.0',
        type: 'module',
        main: 'index.ts',
        scripts: {
          dev: `aisoc-connector dev index.ts`,
          manifest: `aisoc-connector manifest index.ts > manifest.json`,
        },
        dependencies: {
          '@cyble/aisoc-connector': '^0.1.0-beta.1',
          zod: '^3.23.8',
        },
      },
      null,
      2,
    ),
  );
  const safeKind = 'CUSTOM';
  writeFileSync(
    resolve(dir, 'index.ts'),
    [
      "import { defineConnector, ConnectorKind, RiskClass, z } from '@cyble/aisoc-connector';",
      '',
      'export default defineConnector({',
      `  kind: ConnectorKind.${safeKind},`,
      `  vendor: '${name}',`,
      "  version: '0.1.0',",
      "  author: 'You <you@example.com>',",
      '  configSchema: z.object({',
      '    baseUrl: z.string().url(),',
      '    token: z.string().min(1),',
      '  }),',
      '  actions: {',
      '    ping: {',
      "      description: 'Send a tiny GET to /healthz on the upstream.',",
      '      risk: RiskClass.READ,',
      '      idempotent: true,',
      '      input: z.object({}),',
      '      output: z.object({ ok: z.boolean(), latency_ms: z.number() }),',
      '      handler: async ({ ctx }) => {',
      '        const start = Date.now();',
      "        await ctx.http.get('/healthz');",
      '        return { ok: true, latency_ms: Date.now() - start };',
      '      },',
      '    },',
      '  },',
      '});',
      '',
    ].join('\n'),
  );
  writeFileSync(
    resolve(dir, 'README.md'),
    `# ${name}\n\nScaffolded by aisoc-connector init.\n\nNext steps:\n\n    npm i\n    npm run dev\n`,
  );
  process.stderr.write(`Scaffolded ${dir}\n`);
}

switch (cmd) {
  case 'dev':
    runDev(rest);
    break;
  case 'init':
    runInit(rest);
    break;
  case 'manifest':
    runManifest(rest);
    break;
  case '--help':
  case '-h':
  case undefined:
    help();
    process.exit(cmd === undefined ? 2 : 0);
    break;
  default:
    fail(`unknown command: ${cmd}`);
}
