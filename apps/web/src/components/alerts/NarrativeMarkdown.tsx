/**
 * Renderer for the narrative's markdown-light dialect.
 *
 * `services/fusion/app/services/narrative.py` documents its output as
 * "Markdown-light: `**bold**`, bullet lists, blank-line paragraphs. The rail
 * renders these without a full markdown engine. No tables, no headings, no
 * images." The rail was not rendering them at all — it put the string in a
 * `whitespace-pre-wrap` paragraph, so an analyst read the asterisks:
 *
 *     **Medium** alert: Unusual sign-in on **Finance & Legal #2**
 *
 * This covers exactly that dialect and nothing more: `**bold**`, backtick
 * code spans, `- ` bullets, blank-line paragraphs. An unrecognised construct
 * falls through as literal text rather than being silently dropped.
 *
 * It builds React elements, never HTML. The narrative embeds the alert title,
 * entity names and connector-supplied values, all of which originate outside
 * the platform, so `dangerouslySetInnerHTML` here would turn any attacker who
 * can name a host into an XSS author. React escapes text children, and no
 * branch below constructs markup from the input.
 *
 * Whitespace lives inside the parsed text segments rather than between JSX
 * children on separate source lines, which is the arrangement that makes
 * React inject `<!-- -->` separators and drop the leading space.
 */

import { Fragment, type ReactNode } from 'react';

/** Bold and code spans. Split with a capturing group so the delimiters survive. */
const INLINE_TOKEN = /(\*\*[^*\n]+\*\*|`[^`\n]+`)/g;

const BULLET_PREFIX = '- ';

function renderInline(text: string, keyPrefix: string): ReactNode[] {
  return text
    .split(INLINE_TOKEN)
    .filter((segment) => segment !== '')
    .map((segment, index) => {
      const key = `${keyPrefix}i${index}`;
      if (segment.length > 4 && segment.startsWith('**') && segment.endsWith('**')) {
        return (
          <strong key={key} className="font-semibold text-gray-100">
            {segment.slice(2, -2)}
          </strong>
        );
      }
      if (segment.length > 2 && segment.startsWith('`') && segment.endsWith('`')) {
        return (
          <code
            key={key}
            className="rounded bg-gray-800/70 px-1 py-0.5 font-mono text-[0.9em] text-gray-200"
          >
            {segment.slice(1, -1)}
          </code>
        );
      }
      return <Fragment key={key}>{segment}</Fragment>;
    });
}

type Run = { kind: 'text' | 'bullets'; lines: string[] };

/** Group a block's lines into consecutive runs of prose and of bullets. */
function runsFor(block: string): Run[] {
  const runs: Run[] = [];
  for (const line of block.split('\n')) {
    if (line.trim() === '') continue;
    const isBullet = line.trimStart().startsWith(BULLET_PREFIX);
    const kind: Run['kind'] = isBullet ? 'bullets' : 'text';
    const content = isBullet ? line.trimStart().slice(BULLET_PREFIX.length) : line;
    const last = runs[runs.length - 1];
    if (last && last.kind === kind) last.lines.push(content);
    else runs.push({ kind, lines: [content] });
  }
  return runs;
}

export function NarrativeMarkdown({ source }: { source: string }) {
  const blocks = source
    .split(/\n{2,}/)
    .map((block) => block.trim())
    .filter((block) => block !== '');

  return (
    <div className="space-y-2 text-sm leading-relaxed text-gray-300">
      {blocks.flatMap((block, blockIndex) =>
        runsFor(block).map((run, runIndex) => {
          const key = `b${blockIndex}r${runIndex}`;
          if (run.kind === 'bullets') {
            return (
              <ul key={key} className="list-disc space-y-1 pl-5">
                {run.lines.map((line, lineIndex) => (
                  <li key={`${key}l${lineIndex}`}>{renderInline(line, `${key}l${lineIndex}`)}</li>
                ))}
              </ul>
            );
          }
          return (
            <p key={key}>
              {run.lines.flatMap((line, lineIndex) => {
                const nodes = renderInline(line, `${key}l${lineIndex}`);
                // Soft line breaks inside a prose run are preserved as
                // spaces; the dialect has no hard break and re-flowing is
                // what the rail's narrow column wants anyway.
                return lineIndex === 0
                  ? nodes
                  : [<Fragment key={`${key}s${lineIndex}`}> </Fragment>, ...nodes];
              })}
            </p>
          );
        }),
      )}
    </div>
  );
}
