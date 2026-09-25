/**
 * Canvas and palette presentation for each step type.
 *
 * Derived from `STEP_SCHEMAS` rather than declared. This file used to hold a
 * second nine-entry `Record<StepType, …>` beside the one in `stepSchemas`,
 * which meant adding a step type required remembering both — and the thirteen
 * the engine already ran were missing from each.
 */

import type { StepType } from './types';
import { STEP_SCHEMAS, ALL_STEP_TYPES } from './stepSchemas';

export interface StepTypeMeta {
  label: string;
  color: string;
  bgColor: string;
  icon: string;
}

export const STEP_TYPE_META: Record<StepType, StepTypeMeta> = Object.fromEntries(
  ALL_STEP_TYPES.map((type) => {
    const schema = STEP_SCHEMAS[type];
    return [
      type,
      {
        label: schema.label,
        color: schema.accent,
        bgColor: schema.bgColor,
        // The canvas node is too narrow for an emoji plus a name, so it shows
        // the short code; the palette uses `schema.icon`.
        icon: schema.shortCode,
      },
    ];
  }),
) as Record<StepType, StepTypeMeta>;
