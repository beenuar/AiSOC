/**
 * Community submission section. The harness is MIT and reproducible, so
 * any third party can run `python3 scripts/run_evals.py --json --out report.json`
 * against the same fixed dataset and submit their numbers. Submissions go
 * through a structured GitHub issue template
 * (`.github/ISSUE_TEMPLATE/benchmark_submission.yml`); accepted entries are
 * rendered here.
 *
 * Server component — no live fetch yet (the leaderboard starts empty and
 * fills up as submissions are accepted). Future work: a JSON manifest at
 * `eval/community/index.json` on the `eval-results` branch, fetched the
 * same way the latest report is.
 */
const SUBMISSION_URL =
  'https://github.com/beenuar/AiSOC/issues/new?template=benchmark_submission.yml';

const RULES: { title: string; body: string }[] = [
  {
    title: 'Same fixed dataset',
    body: 'Run against the deterministic 200-incident dataset at services/agents/tests/eval_data/synthetic_incidents.json on the commit you submit. No private fixtures.',
  },
  {
    title: 'Same harness',
    body: 'Run scripts/run_evals.py --json --out report.json with no flags that disable gates. Attach the full report.json so per-template macros are auditable.',
  },
  {
    title: 'Open agent or label as closed',
    body: 'If your agent code is open, link it. If it is closed, the entry is still accepted but is labeled "closed-source" so reviewers know they cannot reproduce internals.',
  },
  {
    title: 'No template-stuffing',
    body: 'The three substrate self-consistency suites (MITRE, completeness, response) are gameable by stuffing keywords into reports. Submissions caught doing this are rejected; the alert-reduction measurement is not gameable in the same way.',
  },
];

export function CommunitySubmissions() {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h3 className="text-xl font-semibold tracking-tight text-white">
            Community submissions
          </h3>
          <p className="mt-2 max-w-2xl text-sm text-gray-400">
            The dataset and the harness are MIT and reproducible. Any third
            party &mdash; another open-source project, a vendor, or an
            internal team &mdash; can run the same suite against the same
            200 incidents and submit a result. Accepted entries appear here.
          </p>
        </div>
        <a
          href={SUBMISSION_URL}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-2 rounded-md bg-brand-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-brand-400"
        >
          Submit a run
          <svg
            viewBox="0 0 20 20"
            className="h-3.5 w-3.5"
            fill="currentColor"
            aria-hidden="true"
          >
            <path d="M5.22 14.78a.75.75 0 001.06 0l7.22-7.22v3.69a.75.75 0 001.5 0v-5.5a.75.75 0 00-.75-.75h-5.5a.75.75 0 000 1.5h3.69L5.22 13.72a.75.75 0 000 1.06z" />
          </svg>
        </a>
      </div>

      <h4 className="mt-8 text-sm font-semibold text-white">Submission rules</h4>
      <dl className="mt-3 grid gap-4 sm:grid-cols-2">
        {RULES.map((r) => (
          <div
            key={r.title}
            className="rounded-lg border border-white/5 bg-black/20 p-4"
          >
            <dt className="text-sm font-semibold text-gray-200">{r.title}</dt>
            <dd className="mt-1 text-xs leading-relaxed text-gray-400">
              {r.body}
            </dd>
          </div>
        ))}
      </dl>

      <div className="mt-8 rounded-lg border border-dashed border-white/10 bg-black/20 p-6 text-center">
        <p className="text-sm text-gray-400">
          No accepted community submissions yet.
        </p>
        <p className="mt-1 text-xs text-gray-500">
          The leaderboard fills up as runs are merged. AiSOC&apos;s own numbers
          appear in the cards above.
        </p>
      </div>
    </div>
  );
}
