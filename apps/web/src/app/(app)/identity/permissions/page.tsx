/**
 * Effective-permissions UI page (T3.2).
 *
 * Server-rendered shell that mounts the Cytoscape client behind a dynamic
 * import so we don't ship the cytoscape bundle to the rest of the app. The
 * client reads `?provider=...&principal_id=...` query params and falls back
 * to the deterministic demo principal if neither is set, so the page always
 * has something to render in the screenshot tour and in the smoke test.
 */

import EffectivePermissionsClient from './EffectivePermissionsClient';

export const metadata = {
  title: 'Effective Permissions | AiSOC',
};

export default function EffectivePermissionsPage() {
  return <EffectivePermissionsClient />;
}
