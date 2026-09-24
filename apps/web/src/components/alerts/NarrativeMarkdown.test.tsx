/**
 * The Investigation Rail's Details tab showed analysts the markup.
 *
 * `build_narrative` documents its output as "Markdown-light: `**bold**`,
 * bullet lists, blank-line paragraphs. The rail renders these without a full
 * Markdown engine." The rail put the string in a `whitespace-pre-wrap`
 * paragraph, which preserves the newlines and the asterisks alike, so the
 * panel read:
 *
 *     **Medium** alert: Unusual sign-in ... on **Finance & Legal #2**
 *
 * Two things are being pinned here. The dialect renders (against the
 * pre-change tree every assertion in the first block fails, because the
 * literal `**` was in the DOM). And the renderer builds elements rather than
 * markup: the narrative embeds the alert title and entity names, which come
 * from connectors and are therefore attacker-influenced, so an HTML path here
 * would make anyone who can name a host an XSS author.
 */

import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { NarrativeMarkdown } from './NarrativeMarkdown';

const REAL_NARRATIVE = [
  '**Medium** alert: Unusual sign-in from an unrecognised location on **Finance & Legal #2** from `okta`.',
  '',
  'Why we believe it:',
  '- + **Medium severity from source** — Medium severity from source',
  '- − **Single uncorroborated source** — only one source reported this',
  '- Confidence: **low** (21/100)',
  '',
  'Recommended next step:',
  '- Triage the alert in the queue: confirm whether the activity is sanctioned before escalating.',
].join('\n');

describe('the narrative renders its dialect instead of showing it', () => {
  it('renders bold spans and leaves no asterisks in the text', () => {
    const { container } = render(<NarrativeMarkdown source={REAL_NARRATIVE} />);

    expect(screen.getByText('Medium').tagName).toBe('STRONG');
    expect(screen.getByText('Finance & Legal #2').tagName).toBe('STRONG');
    expect(container.textContent).not.toContain('**');
  });

  it('renders backtick spans as code and drops the backticks', () => {
    const { container } = render(<NarrativeMarkdown source={REAL_NARRATIVE} />);

    expect(screen.getByText('okta').tagName).toBe('CODE');
    expect(container.textContent).not.toContain('`');
  });

  it('renders `- ` lines as list items, not as text beginning with a hyphen', () => {
    const { container } = render(<NarrativeMarkdown source={REAL_NARRATIVE} />);

    const items = container.querySelectorAll('li');
    expect(items.length).toBe(4);
    expect(items[0].textContent).toContain('Medium severity from source');
    // The bullet glyph itself is the list marker now, not part of the text.
    expect(items[0].textContent?.startsWith('- ')).toBe(false);
  });

  it('keeps the lead line of a block as prose above its bullets', () => {
    const { container } = render(<NarrativeMarkdown source={REAL_NARRATIVE} />);

    const paragraphs = [...container.querySelectorAll('p')].map((p) => p.textContent);
    expect(paragraphs).toContain('Why we believe it:');
    expect(paragraphs).toContain('Recommended next step:');
  });

  it('keeps the word spacing around an interpolated span', () => {
    // The JSX trap: an expression and adjacent text on separate source lines
    // makes React inject a comment separator and drop the leading space, so
    // "**Medium** alert" renders as "Mediumalert".
    const { container } = render(<NarrativeMarkdown source={'**Medium** alert: something happened'} />);

    expect(container.textContent).toBe('Medium alert: something happened');
  });

  it('preserves the signs the builder uses for negative factors', () => {
    const { container } = render(<NarrativeMarkdown source={'- − **Single uncorroborated source** — only one source'} />);

    expect(container.textContent).toContain('−');
  });
});

describe('the narrative is never treated as markup', () => {
  it('escapes HTML in an entity name rather than rendering it', () => {
    // A connector can report a hostname, a filename or a URL containing
    // anything. This is the payload that matters: the narrative is built
    // server-side from fields the platform does not control.
    const hostile = '**Medium** alert: beacon on **<img src=x onerror="alert(1)">**';

    const { container } = render(<NarrativeMarkdown source={hostile} />);

    expect(container.querySelector('img')).toBeNull();
    expect(container.textContent).toContain('<img src=x onerror="alert(1)">');
  });

  it('does not let a script tag in the narrative reach the DOM', () => {
    const { container } = render(<NarrativeMarkdown source={'alert: <script>fetch("/x")</script>'} />);

    expect(container.querySelector('script')).toBeNull();
    expect(container.textContent).toContain('<script>fetch("/x")</script>');
  });
});

describe('the narrative degrades rather than dropping content', () => {
  it('leaves an unclosed bold delimiter as literal text', () => {
    const { container } = render(<NarrativeMarkdown source={'**Medium alert with no closing marker'} />);

    expect(container.textContent).toBe('**Medium alert with no closing marker');
    expect(container.querySelector('strong')).toBeNull();
  });

  it('renders an empty narrative as an empty container rather than throwing', () => {
    const { container } = render(<NarrativeMarkdown source={'   \n\n  '} />);

    expect(container.textContent).toBe('');
  });

  it('introduces no heading, so the page heading order is untouched', () => {
    // There is an axe-core WCAG AA gate on heading order, and the rail
    // already owns the section heading above this content.
    const { container } = render(<NarrativeMarkdown source={REAL_NARRATIVE} />);

    expect(container.querySelectorAll('h1,h2,h3,h4,h5,h6').length).toBe(0);
  });
});
