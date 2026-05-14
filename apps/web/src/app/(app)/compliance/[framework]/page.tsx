import { Metadata } from 'next';
import { FrameworkView } from '@/components/compliance/FrameworkView';

interface Props {
  params: Promise<{ framework: string }>;
}

const FRAMEWORK_NAMES: Record<string, string> = {
  soc2: 'SOC 2 Type II',
  iso27001: 'ISO 27001',
  nist_csf: 'NIST CSF',
  pci_dss: 'PCI DSS',
  hipaa: 'HIPAA',
  dora: 'DORA',
};

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { framework } = await params;
  const name = FRAMEWORK_NAMES[framework] ?? framework.toUpperCase();
  return { title: `${name} Compliance` };
}

export default async function ComplianceFrameworkPage({ params }: Props) {
  const { framework } = await params;
  return (
    <div className="p-6">
      <FrameworkView framework={framework} />
    </div>
  );
}
