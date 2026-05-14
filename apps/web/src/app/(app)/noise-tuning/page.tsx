import { redirect } from 'next/navigation';

export const metadata = { title: 'Alert Noise Tuning | AiSOC' };

/**
 * Back-compat redirect. The legacy `/noise-tuning` prototype has been
 * replaced by the API-backed Detection Tuning workbench at
 * `/detection/tuning` (PR-6, W8). Bookmarks and external links land
 * on the new workbench automatically.
 */
export default function NoiseTuningPage() {
  redirect('/detection/tuning');
}
