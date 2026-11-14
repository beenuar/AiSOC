/**
 * Display labels for the marketplace's dotted tag encoding.
 *
 * `scripts/build_marketplace.py` flattens the detection importers' structured
 * tag block — `{'categories': ['endpoint'], 'tlp': ['white']}` — into dotted
 * strings, because everything downstream of it expects `string[]`. That form
 * is an internal encoding and was never meant to be read by a person, but the
 * marketplace card rendered `item.tags` verbatim, so `categories.endpoint`
 * appeared as the only text at the bottom of 5,197 cards and `tlp.white` on
 * 878 more.
 *
 * The namespace decides the label, not a pattern over the string: `tlp.white`
 * is TLP:WHITE, a real classification that would be destroyed by stripping
 * the prefix, while `categories.endpoint` is just the category. An unknown
 * namespace is returned untouched rather than guessed at — that is what makes
 * `tagLabel.test.ts` able to notice a new encoding instead of quietly
 * rendering it, and why this must not become a blanket "strip everything
 * before the first dot".
 */

/** The raw tag and the text a reader should see for it. */
export interface TagLabel {
  label: string;
  /** The raw tag, when it differs — carried as a tooltip so nothing is lost. */
  title?: string;
}

/**
 * Known namespaces from `normalise_tags()`. A namespace listed here has been
 * looked at by a person and given a display form; one that is not listed
 * fails `tagLabel.test.ts` rather than reaching a card.
 */
const NAMESPACE_LABELS: Record<string, (value: string) => string> = {
  // The rule's content category. The card already shows bare category names
  // in its metadata row, so the bare value is the consistent form.
  categories: (value) => value,
  // Traffic Light Protocol. `white` alone would read as a colour.
  tlp: (value) => `TLP:${value.toUpperCase()}`,
  // Which telemetry stream the rule reads.
  data_source: (value) => value,
};

/**
 * Dotted tags that are literal text rather than a namespaced key, so they
 * should render as-is. Empty today; an entry here is a deliberate statement
 * that the dot is part of the value (a hostname, a filename, a version).
 */
const LITERAL_TAGS = new Set<string>();

export function formatTagLabel(tag: string): TagLabel {
  if (LITERAL_TAGS.has(tag)) return { label: tag };
  const dot = tag.indexOf('.');
  if (dot <= 0) return { label: tag };
  const namespace = tag.slice(0, dot);
  const value = tag.slice(dot + 1);
  const render = NAMESPACE_LABELS[namespace];
  if (!render || value === '') return { label: tag };
  const label = render(value);
  return label === tag ? { label } : { label, title: tag };
}

/** The namespaces with a display form, for the gate to read. */
export const KNOWN_TAG_NAMESPACES: readonly string[] = Object.keys(NAMESPACE_LABELS);

/** Declared-literal dotted tags, for the gate to read. */
export const LITERAL_DOTTED_TAGS: ReadonlySet<string> = LITERAL_TAGS;

/**
 * The shape of a machine key that has escaped into user-visible text:
 * a lowercase-initial identifier followed by at least one dotted segment.
 *
 * Broader than `^[a-z][a-zA-Z]*(\.[a-zA-Z]+)+$` by allowing digits and
 * underscores inside a segment, because `data_source.osquery` is exactly the
 * same defect and the narrower form does not match it.
 */
export const RAW_KEY_SHAPE = /^[a-z][a-zA-Z0-9_]*(\.[a-zA-Z0-9_]+)+$/;
