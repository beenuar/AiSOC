/**
 * Transport settings for this service's Kafka client.
 *
 * kafkajs defaults `ssl` and `sasl` to undefined, which is plaintext, and
 * `index.ts` set neither — so the service fanning normalized alerts out to
 * every connected browser read them off the broker in the clear.
 *
 * Mirrors `services/fusion/app/core/kafka_security.py` and
 * `services/ingest/internal/kafkatls`. Three languages cannot share one
 * file, so the rules are restated and `scripts/check_kafka_transport.py`
 * checks all three ends:
 *
 * - production refuses cleartext, by throwing at construction rather than
 *   warning into a log nobody reads;
 * - development defaults to plaintext, because the compose broker has no
 *   certificate;
 * - an unrecognised protocol throws, because the alternative is to fall
 *   back, and the fallback is plaintext.
 */

import { readFileSync } from 'node:fs';
import type { KafkaConfig, SASLOptions } from 'kafkajs';

const VALID_PROTOCOLS = ['PLAINTEXT', 'SSL', 'SASL_PLAINTEXT', 'SASL_SSL'] as const;
type Protocol = (typeof VALID_PROTOCOLS)[number];

const CLEARTEXT: ReadonlySet<Protocol> = new Set<Protocol>(['PLAINTEXT', 'SASL_PLAINTEXT']);
const PROTECTED_ENVIRONMENTS: ReadonlySet<string> = new Set(['production', 'prod', 'staging']);
const TRUTHY: ReadonlySet<string> = new Set(['1', 'true', 'yes', 'on']);

function env(name: string): string {
  return (process.env[name] ?? '').trim();
}

function isProtocol(value: string): value is Protocol {
  return (VALID_PROTOCOLS as readonly string[]).includes(value);
}

/** The `ssl` and `sasl` fields for `new Kafka({...})`. */
export type KafkaTransport = Pick<KafkaConfig, 'ssl' | 'sasl'>;

function saslOptions(): SASLOptions {
  const mechanism = env('KAFKA_SASL_MECHANISM').toLowerCase();
  const username = env('KAFKA_SASL_USERNAME');
  const password = env('KAFKA_SASL_PASSWORD');
  switch (mechanism) {
    case 'plain':
      return { mechanism: 'plain', username, password };
    case 'scram-sha-256':
      return { mechanism: 'scram-sha-256', username, password };
    case 'scram-sha-512':
      return { mechanism: 'scram-sha-512', username, password };
    case '':
      throw new Error(
        'A SASL protocol requires KAFKA_SASL_MECHANISM (for example PLAIN or SCRAM-SHA-512).',
      );
    default:
      throw new Error(`KAFKA_SASL_MECHANISM=${mechanism} is not supported.`);
  }
}

/**
 * Resolve the transport, or throw if it is wrong for this environment.
 *
 * `environment` and `protocol` are parameters so the tests can drive both
 * directions. A running service passes neither: a caller that can choose
 * its own protocol is a caller that can choose plaintext.
 */
export function resolveKafkaTransport(
  environment: string = env('ENVIRONMENT'),
  protocolInput: string = env('KAFKA_SECURITY_PROTOCOL'),
): KafkaTransport {
  const resolvedEnv = environment.toLowerCase();
  const raw = (protocolInput || 'PLAINTEXT').toUpperCase();

  if (!isProtocol(raw)) {
    throw new Error(
      `KAFKA_SECURITY_PROTOCOL=${raw} is not one of ${VALID_PROTOCOLS.join(', ')}. ` +
        'Refusing rather than falling back, because the fallback is plaintext.',
    );
  }

  if (CLEARTEXT.has(raw) && PROTECTED_ENVIRONMENTS.has(resolvedEnv)) {
    if (!TRUTHY.has(env('AISOC_ALLOW_CLEARTEXT_KAFKA').toLowerCase())) {
      throw new Error(
        `ENVIRONMENT=${resolvedEnv} with KAFKA_SECURITY_PROTOCOL=${raw} would read normalized ` +
          'security telemetry off the broker in the clear. Set KAFKA_SECURITY_PROTOCOL=SSL or ' +
          'SASL_SSL, or set AISOC_ALLOW_CLEARTEXT_KAFKA=1 if the broker is reachable only over ' +
          'a network you already encrypt.',
      );
    }
  }

  const transport: KafkaTransport = {};

  if (raw === 'SSL' || raw === 'SASL_SSL') {
    const ca = env('KAFKA_SSL_CAFILE');
    const cert = env('KAFKA_SSL_CERTFILE');
    const key = env('KAFKA_SSL_KEYFILE');
    // `rejectUnauthorized` is left at its default of true. A TLS connection
    // that verifies nothing authenticates nothing, and an operator with a
    // private CA passes it in KAFKA_SSL_CAFILE rather than turning
    // verification off.
    transport.ssl = {
      ...(ca ? { ca: [readFileSync(ca, 'utf8')] } : {}),
      ...(cert ? { cert: readFileSync(cert, 'utf8') } : {}),
      ...(key ? { key: readFileSync(key, 'utf8') } : {}),
    };
  }

  if (raw.startsWith('SASL_')) {
    transport.sasl = saslOptions();
  }

  return transport;
}
