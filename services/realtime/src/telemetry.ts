/**
 * OpenTelemetry tracing for the realtime service.
 *
 * `api`, `agents`, `ueba` and `honeytokens` were instrumented; `ingest`
 * (Go) and `realtime` (TypeScript) were not — and those two are the ends
 * of the Kafka spine. A trace therefore began at the API and stopped at
 * the pipeline boundary, which is where the interesting latency lives: an
 * alert that takes eight seconds to reach a browser is invisible if
 * nothing spans the part that took eight seconds.
 *
 * Three decisions worth stating, all of them about not making things
 * worse:
 *
 * **Off unless an endpoint is configured.** Defaulting it on sends every
 * span into a connection error on deployments with no collector, which
 * fills the logs and makes a missing trace ambiguous between "no span"
 * and "no collector".
 *
 * **Loaded dynamically.** The SDK is an optional dependency, so a
 * deployment that does not want it does not have to install it. A missing
 * package disables tracing with a log line rather than failing to boot —
 * realtime is a fan-out service and must not refuse connections because a
 * telemetry package is absent.
 *
 * **Never throws.** Every path returns a shutdown function, so the
 * caller's shutdown handler is unconditional and cannot be skipped on an
 * error path.
 */

import type pino from 'pino';

export type Shutdown = () => Promise<void>;

const NOOP: Shutdown = async () => {};

/** Strip a URL scheme; the OTLP gRPC exporter wants `host:port`.
 *
 * The Python services accept the URL form in the same environment
 * variable, so accepting both is the difference between one variable and
 * two. Exported for testing — it is the part most likely to be wrong and
 * least likely to be noticed, because a malformed endpoint fails at
 * export time rather than at startup.
 */
export function stripScheme(endpoint: string): string {
  return endpoint
    .replace(/^https?:\/\//, '')
    .replace(/^grpc:\/\//, '')
    .replace(/\/+$/, '');
}

/** Sampling ratio from `OTEL_TRACES_SAMPLER_ARG`, clamped to [0, 1].
 *
 * A value outside the range is a typo, not an instruction; passing it
 * through would either disable sampling entirely or be rejected by the
 * SDK at a point far from the mistake.
 */
export function samplingRatio(raw: string | undefined, fallback = 0.05): number {
  if (raw === undefined || raw.trim() === '') return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(1, Math.max(0, parsed));
}

export async function setupTelemetry(log: pino.Logger): Promise<Shutdown> {
  const endpoint = (process.env.OTEL_EXPORTER_OTLP_ENDPOINT || '').trim();
  if (!endpoint) {
    // Not a warning. A deployment without a collector is supported, and
    // emitting spans nobody collects is worse than emitting none.
    log.debug('tracing disabled: OTEL_EXPORTER_OTLP_ENDPOINT is not set');
    return NOOP;
  }

  try {
    const [{ NodeSDK }, { OTLPTraceExporter }, { resourceFromAttributes }, api] =
      await Promise.all([
        import('@opentelemetry/sdk-node'),
        import('@opentelemetry/exporter-trace-otlp-grpc'),
        import('@opentelemetry/resources'),
        import('@opentelemetry/api'),
      ]);
    const { TraceIdRatioBasedSampler, ParentBasedSampler } = await import(
      '@opentelemetry/sdk-trace-base'
    );

    const sdk = new NodeSDK({
      // `resourceFromAttributes`, not `new Resource`. The 2.x line removed
      // the class constructor. This service was pinned to the 1.30 SDK until
      // four advisories against core, sdk-node, propagator-jaeger and
      // exporter-prometheus forced the move — and 0.217, the floor for
      // sdk-node itself, still pulls a core below *its* floor, so 0.222 is
      // the first version that clears all four.
      resource: resourceFromAttributes({
        'service.name': process.env.OTEL_SERVICE_NAME || 'aisoc-realtime',
        'deployment.environment':
          process.env.AISOC_ENV || process.env.ENVIRONMENT || 'unknown',
      }),
      traceExporter: new OTLPTraceExporter({ url: `http://${stripScheme(endpoint)}` }),
      // Parent-based so a sampled request stays sampled through this hop
      // rather than being re-decided. A trace sampled at one service and
      // dropped at the next is worse than not sampling at all: it looks
      // like the second service did not participate.
      sampler: new ParentBasedSampler({
        root: new TraceIdRatioBasedSampler(
          samplingRatio(process.env.OTEL_TRACES_SAMPLER_ARG),
        ),
      }),
    });

    sdk.start();
    log.info({ endpoint }, 'tracing enabled');

    return async () => {
      try {
        // Flush before exit. An unflushed exporter drops the spans from
        // the final seconds before a restart, and those are
        // disproportionately the ones someone is looking for.
        await sdk.shutdown();
      } catch (err) {
        log.warn({ err }, 'tracing shutdown incomplete; recent spans may be lost');
      }
      void api;
    };
  } catch (err) {
    // A missing optional dependency, or an SDK that would not start.
    // Realtime is a fan-out service and must not refuse connections
    // because telemetry is unavailable.
    log.warn(
      { err },
      'tracing disabled: the OpenTelemetry SDK could not be loaded or started',
    );
    return NOOP;
  }
}
