import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { RoleBadge } from './RoleBadge';

describe('RoleBadge', () => {
  it('renders the canonical label for a known role', () => {
    render(<RoleBadge role="admin" />);
    expect(screen.getByText('Admin')).toBeInTheDocument();
  });

  it('matches role labels case-insensitively', () => {
    render(<RoleBadge role="Analyst" />);
    expect(screen.getByText('Analyst')).toBeInTheDocument();
  });

  it('falls back to "User" for unknown roles', () => {
    render(<RoleBadge role="ops-ninja" />);
    expect(screen.getByText('User')).toBeInTheDocument();
  });

  it('renders the fallback label when role is null', () => {
    render(<RoleBadge role={null} />);
    expect(screen.getByText('User')).toBeInTheDocument();
  });

  it('lets the caller override the visible label', () => {
    render(<RoleBadge role="admin" label="Admin · Acme" />);
    expect(screen.getByText('Admin · Acme')).toBeInTheDocument();
    // The default "Admin" string should no longer be present.
    expect(screen.queryByText('Admin')).not.toBeInTheDocument();
  });

  it('applies the tooltip via title attribute', () => {
    render(<RoleBadge role="responder" tooltip="On-call: 19:00 – 07:00" />);
    const badge = screen.getByText('Responder').closest('span');
    expect(badge).toHaveAttribute('title', 'On-call: 19:00 – 07:00');
  });

  it('forwards a className for layout overrides', () => {
    render(<RoleBadge role="viewer" className="my-custom-class" />);
    const badge = screen.getByText('Viewer').closest('span');
    expect(badge?.className).toContain('my-custom-class');
  });
});
