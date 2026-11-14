import { CoverageView } from '@/components/detections/CoverageView';

export const metadata = {
  title: 'MITRE ATT&CK Coverage',
  description:
    "MITRE ATT&CK coverage matrix derived from AiSOC's shipped detections, broken down by tier (native, imported, community).",
};

export default function CoveragePage() {
  return <CoverageView />;
}
