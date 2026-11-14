import { ReplayEvaluationView } from '@/components/evaluations/ReplayEvaluationView';

export const metadata = {
  title: 'Evaluate on your history',
  description:
    "Measure AiSOC triage against your own analysts' past decisions, on your own closed findings.",
};

// Every read here is tenant-scoped and credential-backed, and a run in flight
// changes between requests. Nothing about it is cacheable.
export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';

export default function EvaluatePage() {
  return <ReplayEvaluationView />;
}
