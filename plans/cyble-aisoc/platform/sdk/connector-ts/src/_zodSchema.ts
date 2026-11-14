/**
 * Small Zod -> JSON Schema converter.
 *
 * The full ``zod-to-json-schema`` package handles every Zod feature,
 * but it's a 60kB dep we don't need. We only support the subset of
 * Zod that connector authors are expected to use:
 *
 *   string, number, boolean, literal, enum, array, object, optional,
 *   nullable, union, record, default
 *
 * Anything outside that set falls back to ``{type: "any"}`` rather
 * than throwing — connector authors get a working manifest, and the
 * Python platform treats unknown shapes as opaque.
 *
 * If we hit a feature we don't handle, the helper returns an
 * ``{x-unsupported: <kind>}`` marker so the marketplace UI can show
 * a "schema not fully described" warning.
 */
import type { ZodTypeAny } from 'zod/v3';

type JsonSchema = Record<string, unknown>;

interface ZodDef {
  typeName?: string;
  innerType?: ZodTypeAny;
  schema?: ZodTypeAny;
  options?: ZodTypeAny[];
  values?: unknown[] | Record<string, string>;
  value?: unknown;
  type?: ZodTypeAny;
  valueType?: ZodTypeAny;
  shape?: () => Record<string, ZodTypeAny>;
  defaultValue?: () => unknown;
  description?: string;
  checks?: Array<{ kind: string; value?: unknown; regex?: RegExp }>;
}

function defOf(s: ZodTypeAny): ZodDef {
  return (s as unknown as { _def: ZodDef })._def ?? {};
}

export function zodToJsonSchema(s: ZodTypeAny): JsonSchema {
  const def = defOf(s);
  const tn = def.typeName ?? '';

  switch (tn) {
    case 'ZodString': {
      const out: JsonSchema = { type: 'string' };
      if (def.description) out.description = def.description;
      for (const c of def.checks ?? []) {
        if (c.kind === 'min') out.minLength = c.value as number;
        else if (c.kind === 'max') out.maxLength = c.value as number;
        else if (c.kind === 'email') out.format = 'email';
        else if (c.kind === 'url') out.format = 'uri';
        else if (c.kind === 'uuid') out.format = 'uuid';
        else if (c.kind === 'regex' && c.regex)
          out.pattern = c.regex.source;
      }
      return out;
    }
    case 'ZodNumber': {
      const out: JsonSchema = { type: 'number' };
      for (const c of def.checks ?? []) {
        if (c.kind === 'int') out.type = 'integer';
        else if (c.kind === 'min') out.minimum = c.value as number;
        else if (c.kind === 'max') out.maximum = c.value as number;
      }
      return out;
    }
    case 'ZodBoolean':
      return { type: 'boolean' };
    case 'ZodNull':
      return { type: 'null' };
    case 'ZodLiteral':
      return { const: def.value };
    case 'ZodEnum': {
      const values = (def.values ?? []) as string[];
      return { type: 'string', enum: values };
    }
    case 'ZodNativeEnum': {
      const values = Object.values(def.values ?? {});
      return { enum: values };
    }
    case 'ZodArray': {
      const inner = def.type;
      return {
        type: 'array',
        items: inner ? zodToJsonSchema(inner) : { type: 'any' as unknown },
      };
    }
    case 'ZodObject': {
      const shape = def.shape ? def.shape() : {};
      const properties: Record<string, JsonSchema> = {};
      const required: string[] = [];
      for (const [key, value] of Object.entries(shape)) {
        const childDef = defOf(value);
        const isOptional = childDef.typeName === 'ZodOptional';
        properties[key] = zodToJsonSchema(value);
        if (!isOptional) required.push(key);
      }
      const out: JsonSchema = { type: 'object', properties };
      if (required.length > 0) out.required = required;
      return out;
    }
    case 'ZodOptional':
    case 'ZodNullable':
    case 'ZodReadonly':
      return def.innerType
        ? zodToJsonSchema(def.innerType)
        : { type: 'any' };
    case 'ZodDefault':
      return def.innerType
        ? { ...zodToJsonSchema(def.innerType), default: def.defaultValue?.() }
        : { type: 'any' };
    case 'ZodUnion':
    case 'ZodDiscriminatedUnion': {
      const opts = def.options ?? [];
      return { anyOf: opts.map((o) => zodToJsonSchema(o)) };
    }
    case 'ZodRecord': {
      const valueType = def.valueType;
      return {
        type: 'object',
        additionalProperties: valueType
          ? zodToJsonSchema(valueType)
          : { type: 'any' as unknown },
      };
    }
    case 'ZodAny':
    case 'ZodUnknown':
      return {};
    default:
      return { 'x-unsupported': tn || 'unknown' };
  }
}
