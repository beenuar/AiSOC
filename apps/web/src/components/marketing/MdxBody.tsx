import Link from 'next/link';
import type { ComponentPropsWithoutRef, ComponentType } from 'react';

/**
 * Local mirror of the `MDXComponents` shape used by `next-mdx-remote`. We
 * deliberately avoid the upstream `mdx/types` import — it requires a separate
 * `@types/mdx` install that isn't pulled in transitively by next-mdx-remote
 * v6, and the only thing we'd get from it is a type alias for this exact
 * record shape.
 */
type MdxComponentsMap = Readonly<Record<string, ComponentType<any>>>;

/**
 * Marketing MDX body styles — applied via the `components` prop on
 * <MDXRemote /> so that prose authored by GTM (in `content/customers/*.mdx`
 * and friends) inherits the landing-page typography palette without each
 * file needing to know about Tailwind classes.
 */
export const mdxBodyComponents: MdxComponentsMap = {
  h1: (props: ComponentPropsWithoutRef<'h1'>) => (
    <h1
      className="mt-12 text-3xl font-semibold tracking-tight text-white first:mt-0 md:text-4xl"
      {...props}
    />
  ),
  h2: (props: ComponentPropsWithoutRef<'h2'>) => (
    <h2
      className="mt-12 text-2xl font-semibold tracking-tight text-white first:mt-0"
      {...props}
    />
  ),
  h3: (props: ComponentPropsWithoutRef<'h3'>) => (
    <h3
      className="mt-8 text-lg font-semibold tracking-tight text-white"
      {...props}
    />
  ),
  p: (props: ComponentPropsWithoutRef<'p'>) => (
    <p className="mt-5 text-base leading-relaxed text-gray-300" {...props} />
  ),
  ul: (props: ComponentPropsWithoutRef<'ul'>) => (
    <ul
      className="mt-5 space-y-2.5 pl-6 text-base leading-relaxed text-gray-300 [&>li]:list-disc [&>li]:marker:text-gray-500"
      {...props}
    />
  ),
  ol: (props: ComponentPropsWithoutRef<'ol'>) => (
    <ol
      className="mt-5 space-y-2.5 pl-6 text-base leading-relaxed text-gray-300 [&>li]:list-decimal [&>li]:marker:text-gray-500"
      {...props}
    />
  ),
  blockquote: (props: ComponentPropsWithoutRef<'blockquote'>) => (
    <blockquote
      className="mt-6 border-l-2 border-brand-500/50 bg-white/[0.02] p-5 text-base italic leading-relaxed text-gray-300"
      {...props}
    />
  ),
  code: (props: ComponentPropsWithoutRef<'code'>) => (
    <code
      className="rounded bg-white/10 px-1.5 py-0.5 font-mono text-[0.85em] text-gray-100"
      {...props}
    />
  ),
  pre: (props: ComponentPropsWithoutRef<'pre'>) => (
    <pre
      className="mt-5 overflow-x-auto rounded-xl border border-white/10 bg-black/40 p-5 font-mono text-sm leading-relaxed text-gray-200"
      {...props}
    />
  ),
  a: ({ href = '#', ...rest }: ComponentPropsWithoutRef<'a'>) => {
    const external = href.startsWith('http');
    if (external) {
      return (
        <a
          href={href}
          target="_blank"
          rel="noreferrer"
          className="text-brand-300 underline decoration-brand-500/40 underline-offset-2 transition hover:text-brand-200"
          {...rest}
        />
      );
    }
    return (
      <Link
        href={href}
        className="text-brand-300 underline decoration-brand-500/40 underline-offset-2 transition hover:text-brand-200"
        {...(rest as Omit<ComponentPropsWithoutRef<'a'>, 'href'>)}
      />
    );
  },
  hr: () => <hr className="my-10 border-white/5" />,
  strong: (props: ComponentPropsWithoutRef<'strong'>) => (
    <strong className="font-semibold text-white" {...props} />
  ),
  em: (props: ComponentPropsWithoutRef<'em'>) => (
    <em className="text-gray-200" {...props} />
  ),
};
