/**
 * Tiny example: an "echo" connector that the dev test runs against.
 *
 * It deliberately doesn't do real HTTP — it returns whatever input
 * you give it. That keeps the example deterministic and tells the
 * platform smoke test "yes, the dev-server -> Python bridge works
 * end to end without us spinning up a real upstream API".
 */
import { defineConnector, ConnectorKind, RiskClass, z } from '../../src/index.js';

export default defineConnector({
  kind: ConnectorKind.CUSTOM,
  vendor: 'echo',
  version: '0.1.0',
  author: 'Cyble AiSOC <ts-sdk@cyble.com>',
  configSchema: z.object({
    baseUrl: z.string().url().default('http://localhost:0'),
    token: z.string().default('dev-token'),
  }),
  actions: {
    echo: {
      description: 'Echo the input back unchanged.',
      risk: RiskClass.READ,
      idempotent: true,
      input: z.object({
        message: z.string().min(1),
        repeat: z.number().int().min(1).max(10).default(1),
      }),
      output: z.object({
        echoes: z.array(z.string()),
        tenant_id: z.string(),
      }),
      handler: async ({ input, ctx }) => {
        ctx.log('info', 'echoing', { repeat: input.repeat });
        return {
          echoes: Array.from({ length: input.repeat }, () => input.message),
          tenant_id: ctx.tenantId,
        };
      },
    },
  },
});
