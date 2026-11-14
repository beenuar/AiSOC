/**
 * Storybook shim for next/link. Renders an ordinary <a> so the
 * navigation contract works in the iframe. Click handlers still fire
 * but the iframe stays put.
 */
import React from 'react';

interface LinkLikeProps extends React.AnchorHTMLAttributes<HTMLAnchorElement> {
  href: string | { pathname: string };
  children?: React.ReactNode;
}

export default function Link({ href, children, ...rest }: LinkLikeProps) {
  const hrefStr = typeof href === 'string' ? href : href.pathname;
  return (
    <a href={hrefStr} {...rest}>
      {children}
    </a>
  );
}
